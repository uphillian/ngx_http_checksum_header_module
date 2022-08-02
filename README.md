# ngx_http_checksum_header_module

Nginx module to calculate a checksum on the file being served and set that as a Header.

I borrowed the nginx spec file and added my module as SOURCE100.

This was just a proof of concept.

# Build

```
git clone <ngx_http_checksum_header_module>.git
tar czf ngx_http_checksum_header_module.tgz ngx_http_checksum_header_module
yumdownloader nginx --source
rpm -Uvh nginx*src.rpm
cp ngx_http_checksum_header_module.tgz ~/rpmbuild/SOURCES/nginx*/
cd ~/rpmbuild/SPECS
rpmbuild -bp nginx-checksum.spec
```
# Install

```
rpm -Uvh nginx-checksum.rpm
```

# Configure

In nginx.conf:

```
load_module ngx_http_checksum_header_module.so
```

In server definition:

```
location / {
  checksum_header sha256;
}
```
