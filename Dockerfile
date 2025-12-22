FROM hashicorp/terraform:1.14.3

RUN apk add --no-cache bash curl git jq make

WORKDIR /terraform