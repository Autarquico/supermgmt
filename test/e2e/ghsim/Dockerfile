# ghsim: the simulated GitHub, Sigstore and OCI registry of the M4 e2e tests (test infrastructure,
# never shipped). The static binary is built by the test harness for the Docker daemon's
# architecture and placed next to this file in the build context; the TLS certificate and key are
# copied in when the container is created.
FROM scratch
COPY ghsim /ghsim
EXPOSE 443 5000 8444
ENTRYPOINT ["/ghsim"]
CMD ["serve", "-cert", "/ghsim.crt", "-key", "/ghsim.key"]
