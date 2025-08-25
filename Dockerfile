FROM hashicorp/terraform:1.13.0

RUN apk add --no-cache bash curl git jq make

WORKDIR /terraform