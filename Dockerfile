# Klarion container image — multi-stage, static, non-root, distroless.
#
# Stage 1 compiles a fully static binary (CGO disabled) so it runs on the
# minimal distroless/static base, which ships no shell or package manager and
# defaults to a non-root user — shrinking the attack surface for a tool that
# handles source code and secrets.

# ---- build stage ----
FROM golang:1.25 AS build

WORKDIR /src

# Cache module downloads separately from source for faster rebuilds.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

ENV CGO_ENABLED=0 GOOS=linux

RUN go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/klarion ./cmd/klarion

# ---- final stage ----
# distroless/static:nonroot provides CA certs and a non-root (65532) user.
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/klarion /usr/local/bin/klarion

USER nonroot:nonroot
WORKDIR /work

ENTRYPOINT ["klarion"]
CMD ["scan", "."]
