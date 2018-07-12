# DM Portal

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/522be124011a4104ad5ecd8af6c7c50c)](https://app.codacy.com/app/Darkmira/dm-portal?utm_source=github.com&utm_medium=referral&utm_content=Darkmira/dm-portal&utm_campaign=Badge_Grade_Dashboard)
[![Build Status](https://travis-ci.org/Darkmira/dm-portal.svg?branch=develop)](https://travis-ci.org/Darkmira/dm-portal)

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

What things you need to install the software and how to install them

```
Docker CE
```

### Installing

A step by step series of commands that tell you have to get a development env running

*(optional)* Override default ports
```bash
cp docker-compose.override.yml.dist docker-compose.override.yml
```

Builds, (re)creates and starts containers in the background
```bash
$ docker-compose up -d
```

Install dependencies
```bash
$ docker-compose exec web composer install --no-interaction
```

Drop, create and update your database
```bash
$ docker-compose exec web php bin/console doctrine:database:drop --force
$ docker-compose exec web php bin/console doctrine:database:create
$ docker-compose exec web php bin/console doctrine:schema:update --force
```
## Loading data fixtures
```bash
docker-compose exec web php bin/console khepin:yamlfixtures:load
```

## Running the tests

```bash
$ docker-compose exec web php vendor/bin/simple-phpunit
```
