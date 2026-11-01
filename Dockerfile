FROM alpine:3.23 AS launcher-build
RUN apk add --no-cache build-base linux-headers
COPY runtime/drop-privileges.c /src/drop-privileges.c
RUN cc -std=c11 -Os -Wall -Wextra -Werror -static \
    -o /drop-privileges /src/drop-privileges.c && strip /drop-privileges

# Stable Alpine 3.23 has 4.0.6; 3.24 has 4.1.2. Avoid mixing in edge packages.
# SHA-256 is published on the upstream 4.1.3 release asset (see upgrade notes).
FROM alpine:3.23 AS transmission-build
RUN apk add --no-cache build-base linux-headers cmake ninja curl xz curl-dev openssl-dev \
    libevent-dev libdeflate-dev miniupnpc-dev libpsl-dev
WORKDIR /src
RUN curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
        --output transmission-4.1.3.tar.xz \
        https://github.com/transmission/transmission/releases/download/4.1.3/transmission-4.1.3.tar.xz \
    && echo 'ce7d2d8b101f7eb54bc3cf0bc55f52f7ebd4a25fa48e00bdca9a7e0fc02617da  transmission-4.1.3.tar.xz' | sha256sum -c - \
    && tar -xJf transmission-4.1.3.tar.xz
RUN cmake -S transmission-4.1.3 -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
        -DENABLE_DAEMON=ON -DENABLE_CLI=OFF -DENABLE_UTILS=OFF \
        -DENABLE_GTK=OFF -DENABLE_QT=OFF -DENABLE_MAC=OFF \
        -DENABLE_TESTS=OFF -DENABLE_NLS=OFF -DINSTALL_DOC=OFF -DINSTALL_LIB=OFF \
        -DINSTALL_WEB=ON -DREBUILD_WEB=OFF -DWITH_SYSTEMD=OFF -DWITH_CRYPTO=openssl \
        -DUSE_SYSTEM_EVENT2=ON -DUSE_SYSTEM_DEFLATE=ON \
        -DUSE_SYSTEM_MINIUPNPC=ON -DUSE_SYSTEM_PSL=ON \
        -DUSE_SYSTEM_DHT=OFF -DUSE_SYSTEM_NATPMP=OFF \
        -DUSE_SYSTEM_UTP=OFF -DUSE_SYSTEM_B64=OFF \
    && cmake --build build --parallel 2 \
    && DESTDIR=/out cmake --install build --strip

# Source archives and dependencies are pinned; no Node runtime is shipped.
FROM node:24.21.0-alpine3.23@sha256:9ec4a2e289874ed0d722e1772ec2de45d2801541db8612f3638b26f128c69ac2 AS webui-build
RUN apk add --no-cache curl git python3 && npm install --global pnpm@10.15.1
WORKDIR /src/modern
RUN curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
        --output /tmp/modern.tar.gz \
        https://api.github.com/repos/jianxcao/transmission-web/tarball/b8e3ff39c9ebeef07bf196ce4bb3ff9236f632f1 \
    && echo '4fab7668c98a2606c301a48b8d67fea8b14a39f62b813f4850be521affcb8bf1  /tmp/modern.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/modern.tar.gz --strip-components=1
COPY webui/transmission-web/compatibility.patch /tmp/compatibility.patch
COPY scripts/collect-node-notices.py /src/scripts/collect-node-notices.py
RUN git apply --check /tmp/compatibility.patch && git apply /tmp/compatibility.patch \
    && pnpm install --frozen-lockfile --registry=https://registry.npmjs.org \
    && printf 'VITE_BASE_URL=/transmission/web\n' > .env.production.local \
    && pnpm run build \
    && python3 /src/scripts/collect-node-notices.py /src/modern/node_modules/.pnpm /src/modern/THIRD-PARTY-NOTICES.txt
WORKDIR /src/legacy
RUN curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
        --output /tmp/legacy.tar.gz \
        https://api.github.com/repos/ronggang/transmission-web-control/tarball/054e2edf7ee1ec859cec3ee5661a550481321a27 \
    && echo '72c0341c5f5a13ec814008ffaa7361f40755c3ebbc1c572301e8d0ae1061bd34  /tmp/legacy.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/legacy.tar.gz --strip-components=1

FROM alpine:3.23
ENV TRANSMISSION_WEB_UI=transmission-web
RUN apk add --no-cache libstdc++ libevent libdeflate miniupnpc libpsl \
        nftables jq openvpn curl ca-certificates iproute2 \
    && mkdir -p /config /data /run/secrets /usr/share/licenses \
    && chmod 0700 /config /run/secrets \
    && awk 'BEGIN { RS=""; FS="\n"; print "Installed Alpine packages and declared license identifiers"; print "License fields come from the Alpine package database; each package retains its own terms." } { package=""; version=""; license="NOASSERTION"; for (i=1; i<=NF; i++) { if ($i ~ /^P:/) package=substr($i,3); else if ($i ~ /^V:/) version=substr($i,3); else if ($i ~ /^L:/) license=substr($i,3) } if (package != "") print package " " version " — " license }' /lib/apk/db/installed > /usr/share/licenses/THIRD-PARTY-NOTICES.alpine.txt
COPY --from=transmission-build /out/usr/bin/transmission-daemon /usr/bin/transmission-daemon
COPY --from=transmission-build /out/usr/share/transmission/ /usr/share/transmission/
COPY --from=webui-build /src/modern/dist/ /usr/share/transmission/web-ui/transmission-web/
COPY --from=webui-build /src/legacy/src/ /usr/share/transmission/web-ui/transmission-web-legacy/
COPY --from=webui-build /src/modern/LICENSE /usr/share/licenses/transmission-web/LICENSE
COPY --from=webui-build /src/modern/THIRD-PARTY-NOTICES.txt /usr/share/licenses/transmission-web/THIRD-PARTY-NOTICES.txt
COPY --from=webui-build /src/legacy/LICENSE /usr/share/licenses/transmission-web-legacy/LICENSE
COPY --from=transmission-build /src/transmission-4.1.3/COPYING /usr/share/licenses/transmission/COPYING
COPY LICENSE /usr/share/licenses/pia-transmission/LICENSE
RUN transmission-daemon --version 2>&1 | grep -E '^transmission-daemon 4\.1\.3([ (]|$)'
COPY --from=launcher-build /drop-privileges /usr/local/bin/drop-privileges
COPY runtime/*.sh /usr/local/lib/pia-transmission/
COPY runtime/pia/ /usr/local/share/pia/
RUN chmod 0755 /usr/local/lib/pia-transmission/*.sh
EXPOSE 9091/tcp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/lib/pia-transmission/entrypoint.sh"]
