import { Component, CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { BrandComponent } from './brand/brand.component';
import type { Brand } from './brand/brand.component';

interface DocLink {
  path: string;
  label: string;
  /** A Material icon, unless the page is about a framework - see `brand`. */
  icon?: string;
  /** The framework's own mark, for the page that introduces its implementation. */
  brand?: Brand;
  /** A page of the implementation above it: indented under it. */
  child?: boolean;
}

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive, MatIconModule, BrandComponent],
  schemas: [CUSTOM_ELEMENTS_SCHEMA],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss',
})
export class AppComponent {
  // One entry per implementation, each followed by its own pages. Quarkus and Go
  // get theirs when their implementation ships: no page documents an API that
  // doesn't exist yet.
  protected readonly links: DocLink[] = [
    { path: '/', label: 'Overview', icon: 'rocket_launch' },
    { path: '/nestjs', label: 'NestJS', brand: 'nestjs' },
    { path: '/nestjs/securing-endpoints', label: 'Protect your routes', icon: 'lock', child: true },
    { path: '/nestjs/parameter-decorators', label: 'Read the caller', icon: 'badge', child: true },
    { path: '/nestjs/info-providers', label: 'Where the identity comes from', icon: 'key', child: true },
    { path: '/nestjs/roles', label: 'Roles', icon: 'account_tree', child: true },
    { path: '/nestjs/reference', label: 'Options reference', icon: 'settings', child: true },
  ];
}
