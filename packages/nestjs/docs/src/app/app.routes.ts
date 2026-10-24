import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    pathMatch: 'full',
    loadComponent: () => import('./pages/getting-started.component').then((m) => m.GettingStartedComponent),
  },
  {
    path: 'securing-endpoints',
    loadComponent: () => import('./pages/securing-endpoints.component').then((m) => m.SecuringEndpointsComponent),
  },
  {
    path: 'parameter-decorators',
    loadComponent: () => import('./pages/parameter-decorators.component').then((m) => m.ParameterDecoratorsComponent),
  },
  {
    path: 'info-providers',
    loadComponent: () => import('./pages/info-providers.component').then((m) => m.PrincipalProvidersComponent),
  },
  {
    path: 'roles',
    loadComponent: () => import('./pages/roles.component').then((m) => m.RolesComponent),
  },
  {
    path: 'reference',
    loadComponent: () => import('./pages/reference.component').then((m) => m.ReferenceComponent),
  },
  // Former pages, merged into the ones above.
  { path: 'ownership', redirectTo: 'securing-endpoints' },
  { path: 'boolean-specs', redirectTo: 'securing-endpoints' },
  { path: 'configuration', redirectTo: 'reference' },
  { path: '**', redirectTo: '' },
];
