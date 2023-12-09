# GRANTED Module for Nestjs

[![Build hhnest/granted](https://github.com/hhnest/granted/actions/workflows/main.yml/badge.svg)](https://github.com/hhnest/granted/actions/workflows/main.yml)

[![Publish hhnest/granted to NPM](https://github.com/hhnest/granted/actions/workflows/tag.yml/badge.svg)](https://github.com/hhnest/granted/actions/workflows/tag.yml)

[![npm version](https://badge.fury.io/js/@hhnest%2Fgranted.svg)](https://badge.fury.io/js/@hhnest%2Fgranted)

This module allow you to use RBAC security on you endpoint nestjs

## Install @hhnest/granted

You can use either the npm or yarn command-line tool to install the `package`.    
Use whichever is appropriate for your project in the examples below.

### NPM

```bash
# @hhnest/granted
npm install @hhnest/granted --save 
```

### YARN

```bash
# @hhnest/granted
yarn add @hhnest/granted
```

### Peer dependence

| name | version |
|---|---|
| @nestjs/common | ^10.0.0 |
| @nestjs/core | ^10.0.0 |
| @nestjs/platform-express | ^10.0.0 |

## Configuration

Just import the module `GrantedModule`, specify the implementation for fetch username, roles  and you can use the `annotations`.   

`AppModule.ts`
```typescript
@Module({
  // Declare the module and define the option apply (for apply or not the security)
  imports: [
    GrantedModule.forRoot({apply: environment.applyAuthGuard}),
  ],
})
export class AppModule {}
```


## Use

### Inject informations

The module allow you to inject informations in your endpoints:

```typescript
@Get('username')
username(@Username() userId: string): Observable<string> {
    return of(userId);
}

@Get('roles')
roles(@Roles() roles: string[]): Observable<string[]> {
    return of(roles);
}

@Get('groups')
groups(@Groups() groups: string[]): Observable<string[]> {
    return of(groups);
}
@Get('locale')
groups(@Locale() locale: string): Observable<string> {
    return of(locale);
}
```

### Secure endpoints

```typescript
@Get('username')
@GrantedTo(and(isAuthenticated(), hasRole('GET_USERNAME')))
username(@Username() userId: string): Observable<string> {
    return of(userId);
}
```

### Details

```typescript
GrantedTo(...booleanSpecs: BooleanSpec[])
```

```typescript
// AndSpec
and(...booleanSpecs: BooleanSpec[]): BooleanSpec
// IsTrueSpec
isTrue(): BooleanSpec
// HasRoleSpec
hasRole(role: string): BooleanSpec
// IsAuthenticatedSpec
isAuthenticated(): BooleanSpec
// IsFalseSpec
isFalse(): BooleanSpec
// NotSpec
not(booleanSpec: BooleanSpec): BooleanSpec
// OrSpec
or(...booleanSpecs: BooleanSpec[]): BooleanSpec
// IsUserSpec
isUser(type: 'Param' | 'Query' | 'Body', field?: string): BooleanSpec
```

### Extends

AppRbacGuard read information in http headers request

username, roles, groups and accept-language

If you want to extract information from other behaviors, just write an other implementation of IGrantedInfoProvider
and set on option

`AppModule.ts`
```typescript
@Module({
  // Declare the module and define the option apply (for apply or not the security)
  providers: [MyGrantedInfoProvider],
  imports: [
    GrantedModule.forRoot({apply: environment.applyAuthGuard, infoProvider: MyGrantedInfoProvider}),
  ],
})
export class AppModule {}
```

This is actualy the default provider

```typescript
export class MyGrantedInfoProvider implements IGrantedInfoProvider {

    getUsernameFromRequest(request: Request): string {
        return JSON.parse(request.header('username') || 'anonymous');
    }

    getRolesFromRequest(request: Request): string[] {
        return JSON.parse(request.header('roles') || '[]');
    }

    getGroupsFromRequest(request: Request): string[] {
        return JSON.parse(request.header('groups') || '[]');
    }

    getLocaleFromRequest(request: Request): string {
        return request.header('accept-language') || 'en';
    }

    getUsernameFromIncomingMessage(incomingMessage: IncomingMessage): string {
        return JSON.parse(incomingMessage.headers('username') || 'anonymous');
    }

    getRolesFromIncomingMessage(incomingMessage: IncomingMessage): string[] {
        return JSON.parse(incomingMessage.headers['roles'] as string || '[]')
    }

    getGroupsFromIncomingMessage(incomingMessage: IncomingMessage): string[] {
        return JSON.parse(incomingMessage.headers['groups'] as string || '[]')
    }

    getLocaleFromIncomingMessage(incomingMessage: IncomingMessage): string {
        return incomingMessage.headers['accept-language'] || 'en';
    }
}
```
