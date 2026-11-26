FROM ruby:4.0-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      libsqlite3-dev \
      pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle config set --local frozen true && bundle install

COPY . .
EXPOSE 4567
CMD ["bundle", "exec", "puma", "-b", "tcp://0.0.0.0:4567", "-t", "1:4"]
