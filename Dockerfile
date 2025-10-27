FROM hashicorp/terraform:1.13.4

RUN apk add --no-cache bash curl git jq make

WORKDIR /terraform