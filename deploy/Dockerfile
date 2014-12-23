FROM progrium/busybox
MAINTAINER dengnan@google.com vmarmol@google.com vishnuk@google.com

# Grab cadvisor from the staging directory.
ADD cadvisor /usr/bin/cadvisor

# Allows cadvisor to run as non-root user.
RUN chmod 0777 /tmp

EXPOSE 8080

ENTRYPOINT ["/usr/bin/cadvisor"]
