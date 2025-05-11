FROM hashicorp/terraform:1.6.6

RUN apk add --no-cache bash curl git jq make

WORKDIR /terraform