FROM appropriate/curl

ENV cache_dir=/cache

VOLUME ${cache_dir}
WORKDIR ${cache_dir}

COPY run.sh /
CMD ["/run.sh"]
