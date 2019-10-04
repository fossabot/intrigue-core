FROM ubuntu:18.04
MAINTAINER Intrigue Team <hello@intrigue.io>
ENV DEBIAN_FRONTEND noninteractive

USER root

# Get intrigue-core code
RUN apt-get -y update && apt-get -y install sudo

# Place base deps here so we don't have to reinstall every time
RUN apt-get -y --fix-broken --no-install-recommends install make \
  git \
  git-core \
  bzip2 \
  autoconf \
  bison \
  build-essential \
  apt-utils \
  software-properties-common \
  lsb-release \
  libssl-dev \
  libyaml-dev \
  libreadline6-dev \
  zlib1g-dev \
  libncurses5-dev \
  libffi-dev \
  libsqlite3-dev \
  net-tools \
  libpq-dev \
  postgresql \
  postgresql-server-dev-all \
  redis-server \
  boxes \
  nmap \
  zmap \
  default-jre \
  thc-ipv6 \
  unzip \
  curl \
  git \
  gcc \
  make \
  libpcap-dev \
  fontconfig \
  locales \
  gconf-service \
  libasound2 \
  libatk1.0-0 \
  libc6 \
  libcairo2 \
  libcups2 \
  libdbus-1-3 \
  libexpat1 \
  libfontconfig1 \
  libgcc1 \
  libgconf-2-4 \
  libgdk-pixbuf2.0-0 \
  libglib2.0-0 \
  libgtk-3-0 \
  libnspr4 \
  libpango-1.0-0 \
  libpangocairo-1.0-0 \
  libstdc++6 \
  libx11-6 \
  libx11-xcb1 \
  libxcb1 \
  libxcomposite1 \
  libxcursor1 \
  libxdamage1 \
  libxext6 \
  libxfixes3 \
  libxi6 \
  libxrandr2 \
  libxrender1 \
  libxss1 \
  libxtst6 \
  ca-certificates \
  fonts-liberation \
  fonts-thai-tlwg \
  libappindicator1 \
  libnss3 \
  lsb-release \
  xdg-utils \
  golang-go \
  dnsmasq \
  systemd \
  python-minimal && \
  rm -rf /var/lib/apt/lists/*

# Migrate!
WORKDIR /core

# Set up intrigue 
ENV BUNDLE_JOBS=12
ENV PATH /root/.rbenv/bin:$PATH
ENV IDIR=/core
ENV DEBIAN_FRONTEND=noninteractive 

# copy intrigue code
COPY . /core/

# get intrigue-specific software & config
RUN /bin/bash /core/util/bootstrap.sh

# Remove the config file so one generates on startup (useful when testing)
RUN rm /core/config/config.json

# Expose the port
EXPOSE 7777

RUN chmod +x /core/util/docker.sh
ENTRYPOINT ["/core/util/docker.sh"]
