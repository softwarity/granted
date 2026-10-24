import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    pathMatch: 'full',
    loadComponent: () => import('./pages/overview.component').then((m) => m.OverviewComponent),
  },
  {
    path: 'nestjs',
    pathMatch: 'full',
    loadComponent: () => import('./pages/getting-started.component').then((m) => m.GettingStartedComponent),
  },
  {
    path: 'nestjs/securing-endpoints',
    loadComponent: () => import('./pages/securing-endpoints.component').then((m) => m.SecuringEndpointsComponent),
  },
  {
    path: 'nestjs/parameter-decorators',
    loadComponent: () => import('./pages/parameter-decorators.component').then((m) => m.ParameterDecoratorsComponent),
  },
  {
    path: 'nestjs/info-providers',
    loadComponent: () => import('./pages/info-providers.component').then((m) => m.PrincipalProvidersComponent),
  },
  {
    path: 'nestjs/roles',
    loadComponent: () => import('./pages/roles.component').then((m) => m.RolesComponent),
  },
  {
    path: 'nestjs/reference',
    loadComponent: () => import('./pages/reference.component').then((m) => m.ReferenceComponent),
  },
  // The NestJS pages, from before the site covered several implementations.
  { path: 'securing-endpoints', redirectTo: 'nestjs/securing-endpoints' },
  { path: 'parameter-decorators', redirectTo: 'nestjs/parameter-decorators' },
  { path: 'info-providers', redirectTo: 'nestjs/info-providers' },
  { path: 'roles', redirectTo: 'nestjs/roles' },
  { path: 'reference', redirectTo: 'nestjs/reference' },
  // Former pages, merged into the ones above.
  { path: 'ownership', redirectTo: 'nestjs/securing-endpoints' },
  { path: 'boolean-specs', redirectTo: 'nestjs/securing-endpoints' },
  { path: 'configuration', redirectTo: 'nestjs/reference' },
  { path: '**', redirectTo: '' },
];
