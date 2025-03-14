#include <HalonMTA.h>
#include <string>
#include <thread>
#include <queue>
#include <mutex>
#include <cstring>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <syslog.h>
#include <memory>
#include <map>

// Halon > 6.1 is linked against libcurl with this feature
#ifndef CURLOPT_AWS_SIGV4
#define CURLOPT_AWS_SIGV4 (CURLoption)(CURLOPTTYPE_STRINGPOINT + 305)
#endif

struct curlMulti
{
       std::string id;
       std::mutex lock;
       CURLM* handle;
       std::thread tid;
       std::queue<CURL*> curls;
       bool quit = false;
};

static std::map<std::string, std::unique_ptr<curlMulti>> curlMultis;

struct sslcert
{
	X509 *x509 = nullptr;
	EVP_PKEY *pkey = nullptr;
	STACK_OF(X509) *chain = nullptr;
	bool chain_free = false;
};

struct halon {
	HalonHSLContext *hhc = nullptr;
	HalonHSLValue* ret = nullptr;
	struct curl_slist *headers = nullptr;
	curl_mime *mime = nullptr;
	void *user = nullptr;
	EVP_ENCODE_CTX *evp = nullptr;
	FILE *fp = nullptr;
	curl_off_t max_file_size = 0;
	sslcert cert;
};

HALON_EXPORT
int Halon_version()
{
	return HALONMTA_PLUGIN_VERSION;
}

HALON_EXPORT
void Halon_cleanup()
{
	for (auto & cm : curlMultis)
	{
		cm.second->lock.lock();
		cm.second->quit = true;
		cm.second->lock.unlock();
		curl_multi_wakeup(cm.second->handle);
		cm.second->tid.join();
	}
}

static size_t read_callback(char *dest, size_t size, size_t nmemb, FILE *fp)
{
	size_t x = fread(dest, size, nmemb, fp);
	return x;
}

static size_t read_callback_evp(char *dest, size_t size, size_t nmemb, halon *h)
{
	unsigned char buf[65524 / 2]; // XXX: large safety margin
	size_t x = fread(buf, 1, sizeof(buf), h->fp);
	int destlen;
	if (x == 0)
		EVP_EncodeFinal(h->evp, (unsigned char*)dest, &destlen);
	else
		EVP_EncodeUpdate(h->evp, (unsigned char*)dest, &destlen, buf, (int)x);
	return destlen;
}

static size_t write_callback(char *data, size_t size, size_t nmemb, halon* h)
{
	if (h->user == nullptr)
		return 0;
	if (h->max_file_size > 0)
		if (((std::string*)h->user)->size() + (size * nmemb) > (unsigned long)h->max_file_size)
			return 0;
	((std::string*)h->user)->append((const char*)data, size * nmemb);
	return size * nmemb;
}

static CURLcode sslctx_function(CURL *curl, void *sslctx, void *param)
{
	sslcert* cert = (sslcert*)param;
	if (SSL_CTX_use_cert_and_key((SSL_CTX*)sslctx, cert->x509, cert->pkey, cert->chain, 1) <= 0)
		return CURLE_ABORTED_BY_CALLBACK;
	if (!SSL_CTX_check_private_key((SSL_CTX*)sslctx))
		return CURLE_ABORTED_BY_CALLBACK;
	return CURLE_OK;
}

static void http_background(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	const char *id = nullptr;
	HalonHSLValue* id_ = HalonMTA_hsl_argument_get(args, 0);
	if (!id_ || (HalonMTA_hsl_value_type(id_) != HALONMTA_HSL_TYPE_STRING ||
		!HalonMTA_hsl_value_get(id_, HALONMTA_HSL_TYPE_STRING, &id, nullptr)))
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad ID parameter", 0);
		return;
	}

	auto cm = curlMultis.find(id);
	if (cm == curlMultis.end())
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Missing ID in configuration", 0);
		return;
	}

	const char *url = nullptr;
	HalonHSLValue* url_ = HalonMTA_hsl_argument_get(args, 1);
	if (!url_ || (HalonMTA_hsl_value_type(url_) != HALONMTA_HSL_TYPE_STRING ||
		!HalonMTA_hsl_value_get(url_, HALONMTA_HSL_TYPE_STRING, &url, nullptr)))
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad URL parameter", 0);
		return;
	}

	HalonHSLValue* options = HalonMTA_hsl_argument_get(args, 2);
	if (options && HalonMTA_hsl_value_type(options) != HALONMTA_HSL_TYPE_ARRAY)
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad options parameter", 0);
		return;
	}

	bool tls_verify_peer = true;
	const HalonHSLValue *hv_tls_verify_peer = HalonMTA_hsl_value_array_find(options, "tls_verify_peer");
	if (hv_tls_verify_peer && !HalonMTA_hsl_value_get(hv_tls_verify_peer, HALONMTA_HSL_TYPE_BOOLEAN, &tls_verify_peer, nullptr))
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad tls_verify_peer value", 0);
		return;
	}

	bool tls_verify_host = true;
	const HalonHSLValue *hv_tls_verify_host = HalonMTA_hsl_value_array_find(options, "tls_verify_host");
	if (hv_tls_verify_host && !HalonMTA_hsl_value_get(hv_tls_verify_host, HALONMTA_HSL_TYPE_BOOLEAN, &tls_verify_host, nullptr))
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad tls_verify_host value", 0);
		return;
	}

	sslcert cert;
	const HalonHSLValue *hv_tls_client_cert = HalonMTA_hsl_value_array_find(options, "tls_client_cert");
	if (hv_tls_client_cert)
	{
		if (HalonMTA_hsl_value_type(hv_tls_client_cert) != HALONMTA_HSL_TYPE_ARRAY)
		{
			HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
			HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad tls_client_cert value", 0);
			return;
		}

		const HalonHSLValue *hv_tls_client_cert_x509 = HalonMTA_hsl_value_array_find(hv_tls_client_cert, "x509");
		if (!HalonMTA_hsl_value_get(hv_tls_client_cert_x509, HALONMTA_HSL_TYPE_X509, &cert.x509, nullptr))
		{
			HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
			HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad x509 value", 0);
			return;
		}

		const HalonHSLValue *hv_tls_client_cert_privatekey = HalonMTA_hsl_value_array_find(hv_tls_client_cert, "privatekey");
		if (!HalonMTA_hsl_value_get(hv_tls_client_cert_privatekey, HALONMTA_HSL_TYPE_PRIVATEKEY, &cert.pkey, nullptr))
		{
			HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
			HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad privatekey value", 0);
			return;
		}

		const HalonHSLValue *hv_tls_client_cert_chain = HalonMTA_hsl_value_array_find(hv_tls_client_cert, "chain");
		if (hv_tls_client_cert_chain)
		{
			if (HalonMTA_hsl_value_type(hv_tls_client_cert_chain) != HALONMTA_HSL_TYPE_ARRAY)
			{
				HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
				HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad chain value", 0);
				return;
			}
			cert.chain_free = true;
			cert.chain = sk_X509_new_null();
			size_t index = 0;
			HalonHSLValue *v;
			while ((v = HalonMTA_hsl_value_array_get(hv_tls_client_cert_chain, index++, nullptr)))
			{
				X509* x = nullptr;
				if (!HalonMTA_hsl_value_get(v, HALONMTA_HSL_TYPE_X509, &x, nullptr))
				{
					HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
					HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad x509 value in chain", 0);
					sk_X509_free(cert.chain);
					return;
				}
				sk_X509_push(cert.chain, x);
			}
		}
	}

	long timeout = 0;
	const HalonHSLValue *hv_timeout = HalonMTA_hsl_value_array_find(options, "timeout");
	if (hv_timeout)
	{
		double timeout_;
		if (!HalonMTA_hsl_value_get(hv_timeout, HALONMTA_HSL_TYPE_NUMBER, &timeout_, nullptr))
		{
			HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
			HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad timeout value", 0);
			return;
		}
		timeout = (long)timeout_;
	}

	long connect_timeout = 0;
	const HalonHSLValue *hv_connect_timeout = HalonMTA_hsl_value_array_find(options, "connect_timeout");
	if (hv_timeout)
	{
		double connect_timeout_;
		if (!HalonMTA_hsl_value_get(hv_connect_timeout, HALONMTA_HSL_TYPE_NUMBER, &connect_timeout_, nullptr))
		{
			HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
			HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad connect_timeout value", 0);
			return;
		}
		connect_timeout = (long)connect_timeout_;
	}

	long max_file_size = 0;
	const HalonHSLValue *hv_max_file_size = HalonMTA_hsl_value_array_find(options, "max_file_size");
	if (hv_max_file_size)
	{
		double max_file_size_;
		if (!HalonMTA_hsl_value_get(hv_max_file_size, HALONMTA_HSL_TYPE_NUMBER, &max_file_size_, nullptr))
		{
			HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
			HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad max_file_size value", 0);
			return;
		}
		max_file_size = (long)max_file_size_;
	}

	const char *encoder = nullptr;
	const HalonHSLValue *hv_encoder = HalonMTA_hsl_value_array_find(options, "encoder");
	if (hv_encoder && !HalonMTA_hsl_value_get(hv_encoder, HALONMTA_HSL_TYPE_STRING, &encoder, nullptr))
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad encoder value", 0);
		return;
	}
	bool base64_encode = encoder && strcmp(encoder, "base64") == 0;

	const char *proxy = nullptr;
	const HalonHSLValue *hv_proxy = HalonMTA_hsl_value_array_find(options, "proxy");
	if (hv_proxy && !HalonMTA_hsl_value_get(hv_proxy, HALONMTA_HSL_TYPE_STRING, &proxy, nullptr))
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad proxy value", 0);
		return;
	}

	const char *method = nullptr;
	const HalonHSLValue *hv_method = HalonMTA_hsl_value_array_find(options, "method");
	if (hv_method && !HalonMTA_hsl_value_get(hv_method, HALONMTA_HSL_TYPE_STRING, &method, nullptr))
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad method value", 0);
		return;
	}

	const char *sourceip = nullptr;
	const HalonHSLValue *hv_sourceip = HalonMTA_hsl_value_array_find(options, "sourceip");
	if (hv_sourceip && !HalonMTA_hsl_value_get(hv_sourceip, HALONMTA_HSL_TYPE_STRING, &sourceip, nullptr))
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad sourceip value", 0);
		return;
	}

	const char *username = nullptr;
	const HalonHSLValue *hv_username = HalonMTA_hsl_value_array_find(options, "username");
	if (hv_username && !HalonMTA_hsl_value_get(hv_username, HALONMTA_HSL_TYPE_STRING, &username, nullptr))
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad username value", 0);
		return;
	}

	const char *password = nullptr;
	const HalonHSLValue *hv_password = HalonMTA_hsl_value_array_find(options, "password");
	if (hv_password && !HalonMTA_hsl_value_get(hv_password, HALONMTA_HSL_TYPE_STRING, &password, nullptr))
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad password value", 0);
		return;
	}

	const char *aws_sigv4 = nullptr;
	const HalonHSLValue *hv_aws_sigv4 = HalonMTA_hsl_value_array_find(options, "aws_sigv4");
	if (hv_aws_sigv4 && !HalonMTA_hsl_value_get(hv_aws_sigv4, HALONMTA_HSL_TYPE_STRING, &aws_sigv4, nullptr))
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad aws_sigv4 value", 0);
		return;
	}

	auto h = new halon;
	h->hhc = hhc;
	h->ret = ret;
	h->user = (void*)new std::string;
	h->max_file_size = max_file_size;
	h->cert = cert;

	CURL *curl = curl_easy_init();

	bool hasContentType = false;
	const HalonHSLValue *hv_headers = HalonMTA_hsl_value_array_find(options, "headers");
	if (hv_headers)
	{
		size_t index = 0;
		HalonHSLValue *k, *v;
		while ((v = HalonMTA_hsl_value_array_get(hv_headers, index, &k)))
		{
			const char *header = nullptr;
			if (HalonMTA_hsl_value_get(v, HALONMTA_HSL_TYPE_STRING, &header, nullptr))
			{
				if (!hasContentType && strncasecmp(header, "Content-Type:", 13) == 0)
					hasContentType = true;
				h->headers = curl_slist_append(h->headers, header);
			}
			++index;
		}
	}

	HalonHSLValue* post_ = HalonMTA_hsl_argument_get(args, 3);
	if (post_)
	{
		if (HalonMTA_hsl_value_type(post_) == HALONMTA_HSL_TYPE_FILE)
		{
			FILE* fp = nullptr;
			if (!HalonMTA_hsl_value_get(post_, HALONMTA_HSL_TYPE_FILE, &fp, nullptr))
			{
				HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
				HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad POST parameter", 0);
				return;
			}
			if (base64_encode)
			{
				h->fp = fp;
				h->evp = EVP_ENCODE_CTX_new();
				EVP_EncodeInit(h->evp);
				curl_easy_setopt(curl, CURLOPT_READFUNCTION, ::read_callback_evp);
				curl_easy_setopt(curl, CURLOPT_READDATA, (void*)h);
			}
			else
			{
				curl_easy_setopt(curl, CURLOPT_READFUNCTION, ::read_callback);
				curl_easy_setopt(curl, CURLOPT_READDATA, (void*)fp);
			}
			curl_easy_setopt(curl, CURLOPT_POST, 1);
			if (!hasContentType)
				h->headers = curl_slist_append(h->headers, "Content-Type: application/octet-stream");
		}
		else if (HalonMTA_hsl_value_type(post_) == HALONMTA_HSL_TYPE_ARRAY)
		{
			h->mime = curl_mime_init(curl);
			size_t index = 0;
			HalonHSLValue *k, *v;
			while ((v = HalonMTA_hsl_value_array_get(post_, index, &k)))
			{
				curl_mimepart *field = curl_mime_addpart(h->mime);
				const char *data = nullptr;
				size_t datalen;

				if (HalonMTA_hsl_value_get(k, HALONMTA_HSL_TYPE_STRING, &data, nullptr))
					curl_mime_name(field, data);

				const HalonHSLValue *hv_field_data = HalonMTA_hsl_value_array_find(v, "data");
				if (HalonMTA_hsl_value_type(hv_field_data) == HALONMTA_HSL_TYPE_FILE)
				{
					FILE* fp = nullptr;
					if (HalonMTA_hsl_value_get(hv_field_data, HALONMTA_HSL_TYPE_FILE, &fp, nullptr))
					{
						fseek(fp, 0, SEEK_END);
						size_t length = ftell(fp);
						fseek(fp, 0, SEEK_SET);
						curl_mime_data_cb(field, length, (curl_read_callback)fread, (curl_seek_callback)fseek, nullptr, (void*)fp);
					}
				}
				else if (HalonMTA_hsl_value_type(hv_field_data) == HALONMTA_HSL_TYPE_STRING)
				{
					if (HalonMTA_hsl_value_get(hv_field_data, HALONMTA_HSL_TYPE_STRING, &data, &datalen))
						curl_mime_data(field, data, datalen);
				}
				else
				{
					HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
					HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad data type", 0);
				}

				const HalonHSLValue *hv_field_type = HalonMTA_hsl_value_array_find(v, "type");
				if (HalonMTA_hsl_value_get(hv_field_type, HALONMTA_HSL_TYPE_STRING, &data, &datalen))
					curl_mime_type(field, data);

				const HalonHSLValue *hv_field_filename = HalonMTA_hsl_value_array_find(v, "filename");
				if (HalonMTA_hsl_value_get(hv_field_filename, HALONMTA_HSL_TYPE_STRING, &data, &datalen))
					curl_mime_filename(field, data);

				const HalonHSLValue *hv_field_encoder = HalonMTA_hsl_value_array_find(v, "encoder");
				if (HalonMTA_hsl_value_get(hv_field_encoder, HALONMTA_HSL_TYPE_STRING, &data, &datalen))
					curl_mime_encoder(field, data);

				++index;
			}
			curl_easy_setopt(curl, CURLOPT_MIMEPOST, h->mime);
		}
		else if (HalonMTA_hsl_value_type(post_) == HALONMTA_HSL_TYPE_STRING)
		{
			const char *data = nullptr;
			size_t datalen;
			HalonMTA_hsl_value_get(post_, HALONMTA_HSL_TYPE_STRING, &data, &datalen);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, datalen);
			curl_easy_setopt(curl, CURLOPT_POST, 1);
		}
		else
		{
			HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
			HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad type of POST parameter", 0);
			return;
		}
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_PRIVATE, (void*)h);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ::write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, h);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, h->headers);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);

	if (timeout)
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
	if (connect_timeout)
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout);
	if (!tls_verify_host)
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	if (!tls_verify_peer)
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	if (proxy)
		curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
	if (method)
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
	if (sourceip)
		curl_easy_setopt(curl, CURLOPT_INTERFACE, sourceip);
	if (username)
		curl_easy_setopt(curl, CURLOPT_USERNAME, username);
	if (password)
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
	if (aws_sigv4)
		curl_easy_setopt(curl, CURLOPT_AWS_SIGV4, aws_sigv4);
	if (max_file_size)
		curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, max_file_size);
	if (cert.x509 && cert.pkey)
	{
		curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, &h->cert);
		curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, *sslctx_function);
	}

	cm->second->lock.lock();
	cm->second->curls.push(curl);
	cm->second->lock.unlock();
	curl_multi_wakeup(cm->second->handle);

	HalonMTA_hsl_suspend_return(hhc);
}

HALON_EXPORT
bool Halon_hsl_register(HalonHSLRegisterContext* hhrc)
{
	HalonMTA_hsl_module_register_function(hhrc, "http_background", http_background);
	return true;
}

HALON_EXPORT
bool Halon_init(HalonInitContext* hic)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);

	HalonConfig* cfg = nullptr;
	HalonMTA_init_getinfo(hic, HALONMTA_INIT_CONFIG, nullptr, 0, &cfg, nullptr);
	if (!cfg)
		return false;

	auto threads = HalonMTA_config_object_get(cfg, "threads");
	if (threads)
	{
		size_t l = 0;
		HalonConfig* thread;
		while ((thread = HalonMTA_config_array_get(threads, l++)))
		{
			auto x = std::make_shared<curlMulti>();

			const char* id = HalonMTA_config_string_get(HalonMTA_config_object_get(thread, "id"), nullptr);
			if (!id)
			{
				syslog(LOG_CRIT, "No threads.id");
				return false;
			}
			const char* maxtotal = HalonMTA_config_string_get(HalonMTA_config_object_get(thread, "max_total"), nullptr);
			const char* maxhost = HalonMTA_config_string_get(HalonMTA_config_object_get(thread, "max_hosts"), nullptr);

			std::unique_ptr<curlMulti> cmptr = std::make_unique<curlMulti>();
			cmptr->id = id;
			cmptr->handle = curl_multi_init();
			if (maxtotal)
				curl_multi_setopt(cmptr->handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, strtoul(maxtotal, nullptr, 10));
			if (maxhost)
				curl_multi_setopt(cmptr->handle, CURLMOPT_MAX_HOST_CONNECTIONS, strtoul(maxhost, nullptr, 10));
			auto cm = cmptr.get();
			cmptr->tid = std::thread([cm, id] () {
					pthread_setname_np(pthread_self(), std::string(std::string("p/hb/") + id).substr(0, 15).c_str());
					do {
					int still_running;
					CURLMcode mc = curl_multi_perform(cm->handle, &still_running);
					struct CURLMsg *m;
					do {
						int msgq = 0;
						m = curl_multi_info_read(cm->handle, &msgq);
						if (m && (m->msg == CURLMSG_DONE))
						{
							CURL *e = m->easy_handle;

							halon *h;
							curl_easy_getinfo(e, CURLINFO_PRIVATE, &h);

							if (m->data.result != CURLE_OK)
							{
								HalonHSLValue *k, *v;
								HalonMTA_hsl_value_array_add(h->ret, &k, &v);
								HalonMTA_hsl_value_set(k, HALONMTA_HSL_TYPE_STRING, "error", 0);
								HalonMTA_hsl_value_set(v, HALONMTA_HSL_TYPE_STRING, curl_easy_strerror(m->data.result), 0);
							}
							else
							{
								long status;
								curl_easy_getinfo(e, CURLINFO_RESPONSE_CODE, &status);

								HalonHSLValue *k, *v;
								HalonMTA_hsl_value_array_add(h->ret, &k, &v);
								HalonMTA_hsl_value_set(k, HALONMTA_HSL_TYPE_STRING, "status", 0);
								double status_ = (double)status;
								HalonMTA_hsl_value_set(v, HALONMTA_HSL_TYPE_NUMBER, &status_, 0);
								HalonMTA_hsl_value_array_add(h->ret, &k, &v);
								HalonMTA_hsl_value_set(k, HALONMTA_HSL_TYPE_STRING, "content", 0);
								HalonMTA_hsl_value_set(v, HALONMTA_HSL_TYPE_STRING, ((std::string*)h->user)->c_str(), 0);
							}

							HalonMTA_hsl_schedule(h->hhc);
							delete (std::string*)h->user;
							curl_slist_free_all(h->headers);
							curl_mime_free(h->mime);
							EVP_ENCODE_CTX_free(h->evp);
							if (h->cert.chain_free) sk_X509_free(h->cert.chain);
							delete h;

							curl_multi_remove_handle(cm->handle, e);
							curl_easy_cleanup(e);
						}
					} while (m);

					int numfds;
					mc = curl_multi_poll(cm->handle, nullptr, 0, 10000, &numfds);

					cm->lock.lock();
					while (!cm->curls.empty())
					{
						CURL *curl = cm->curls.front();
						curl_multi_add_handle(cm->handle, curl);
						cm->curls.pop();
					}
					cm->lock.unlock();
				} while (!cm->quit);
			});
			curlMultis.insert(std::make_pair(id, std::move(cmptr)));
		}
	}

	return true;
}