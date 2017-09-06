FROM php:7.1-alpine
WORKDIR /var/www/html
# Composer
RUN curl -sS https://getcomposer.org/installer | php -- --filename=composer --install-dir=/usr/local/bin \
    && composer global require "hirak/prestissimo:^0.3"

CMD ["php", "bin/console", "server:run", "0.0.0.0:80"]
