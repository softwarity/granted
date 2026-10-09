import { Component, CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';

interface DocLink {
  path: string;
  label: string;
  icon: string;
}

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive, MatIconModule],
  schemas: [CUSTOM_ELEMENTS_SCHEMA],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss',
})
export class AppComponent {
  protected readonly links: DocLink[] = [
    { path: '/', label: 'Getting started', icon: 'rocket_launch' },
    { path: '/securing-endpoints', label: 'Protect your routes', icon: 'lock' },
    { path: '/parameter-decorators', label: 'Read the caller', icon: 'badge' },
    { path: '/info-providers', label: 'Where the identity comes from', icon: 'key' },
    { path: '/roles', label: 'Roles', icon: 'account_tree' },
    { path: '/reference', label: 'Options reference', icon: 'settings' },
  ];
}
