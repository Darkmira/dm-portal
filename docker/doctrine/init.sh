#!/bin/sh

php /app/bin/console doctrine:database:create
php /app/bin/console doctrine:schema:create
php /app/bin/console khepin:yamlfixtures:load 
