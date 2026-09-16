# Changelog

## 0.1.0 (2026-09-16)


### ⚠ BREAKING CHANGES

* generated clients moved from Lock\Client\{Admin,Auth,Management} to Lock\Client\OpenApi\{Admin,Auth,Management}.
* RealmsApi and realm models moved to Lock\Client\Admin, and Lock\Client\Oidc was renamed to Lock\Client\Auth.

### Features

* add generated standalone PHP client ([6969cfd](https://github.com/use-lock/client-php/commit/6969cfdee0dca0ebc368a94513a9c53d8ddbf042))
* add OIDC discovery and token validation ([10dd005](https://github.com/use-lock/client-php/commit/10dd00517fd3e10d8fbfe521357bf50d2039a0aa))
* generate admin, auth and management clients from GitHub specs ([1a8e0de](https://github.com/use-lock/client-php/commit/1a8e0dea44dfb016794c4cc6e4a53170730278f7))


### Refactoring

* move generated clients into the OpenApi namespace ([a4836db](https://github.com/use-lock/client-php/commit/a4836db2dd69befe7a27f994e29ae3b51161e4ea))
