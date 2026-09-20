# Test-only image: no physical network or production state is ever attached.
FROM scratch
COPY netagent-lab /netagent-lab
USER 0:0
ENTRYPOINT ["/netagent-lab"]
