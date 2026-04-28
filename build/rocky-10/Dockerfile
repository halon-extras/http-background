FROM rockylinux/rockylinux:10.1
LABEL org.opencontainers.image.authors="support@halon.io"

ARG TARGETARCH
ARG TARGETOS

ARG HALON_REPO_USER
ARG HALON_REPO_PASS

RUN dnf update -y && dnf install -y epel-release

RUN echo "[halon]" >> /etc/yum.repos.d/Halon.repo
RUN echo "name=Halon repository" >> /etc/yum.repos.d/Halon.repo
RUN echo "baseurl=https://${HALON_REPO_USER}:${HALON_REPO_PASS}@repo.halon.io/dists/rhel10/${TARGETARCH}/stable" >> /etc/yum.repos.d/Halon.repo
RUN echo "gpgcheck=1" >> /etc/yum.repos.d/Halon.repo
RUN echo "gpgkey=https://raw.githubusercontent.com/halon/pgp-keys/master/pgp-keys/7F0A73B5.asc" >> /etc/yum.repos.d/Halon.repo
RUN echo "enabled=1" >> /etc/yum.repos.d/Halon.repo
RUN dnf install -y halon-6.11.0

RUN dnf install -y cmake make gcc-c++ rpm-build autoconf openssl-devel
RUN mkdir /tmp/halon
RUN cd /tmp/halon \
    && curl -O -L https://github.com/curl/curl/releases/download/curl-7_80_0/curl-7.80.0.tar.gz \
    && echo "dab997c9b08cb4a636a03f2f7f985eaba33279c1c52692430018fae4a4878dc7 curl-7.80.0.tar.gz" | sha256sum -c \
    && tar -zxvf curl-7.80.0.tar.gz && cd curl-7.80.0 \
    && LD_LIBRARY_PATH=/usr/local/lib64 ./configure --without-ssl --without-ldap \
    && make && make install \
    && cp /usr/local/lib/pkgconfig/libcurl.pc /usr/lib64/pkgconfig/ \
    && rm /usr/local/bin/curl
RUN rm -rf /tmp/halon
RUN echo -n "ROCKY10" > /OSRELEASE.txt

COPY build.sh /build.sh
CMD ["/build.sh"]
