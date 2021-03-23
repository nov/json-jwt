FROM ruby:2.3.7
ARG BUNDLE_GEM_FURY_IO
ENV APP_HOME /app
RUN apt-get update -qq && apt-get install -y build-essential

# Install development tools
RUN apt-get -y install vim

# install openssl
RUN apt-get -y install openssl

RUN mkdir $APP_HOME
WORKDIR $APP_HOME

ADD Gemfile* $APP_HOME/
RUN gem install ruby-debug-ide --pre
COPY . $APP_HOME
RUN gem install bundler -v 1.17.3 && bundle install

