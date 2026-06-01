export interface ThemeSettings {
  logo?: {
    src: string;
    title?: string;
    alt?: string;
    width?: string;
    height?: string;
  };
  loginLogo?: {
    src: string;
    title?: string;
    alt?: string;
    width?: string;
    height?: string;
  };
  footer?: {
    mailto?: string;
    phone?: string;
  };
}

export interface ThemeDefinition {
  stylesheets?: string[];
  path?: string;
  icon?: string;
  settings?: ThemeSettings;
}

export interface ThemeMapping {
  theme: string;
  realms?: (string | RegExp)[];
  authenticationChains?: (string | RegExp)[];
}

export interface ThemeConfig {
  themes: Record<string, ThemeDefinition>;
  mappings?: ThemeMapping[];
}

export const themeConfiguration: ThemeConfig = {
  themes: {
    default: {
      stylesheets: ['css/bootstrap-3.3.5-custom.css', 'css/structure.css', 'css/theme.css'],
      path: '',
      icon: 'favicon.ico',
      settings: {
        logo: {
          src: 'images/login-logo.png',
          title: 'OpenAM',
          alt: 'OpenAM',
          width: '225px',
        },
        loginLogo: {
          src: 'images/login-logo.png',
          title: 'OpenAM',
          alt: 'OpenAM',
          height: '57px',
          width: '225px',
        },
        footer: {
          mailto: 'open-identity-platform-openam@googlegroups.com',
          phone: '',
        },
      },
    },
    'fr-dark-theme': {
      stylesheets: [
        'themes/dark/css/bootstrap.min.css',
        'css/structure.css',
        'themes/dark/css/theme-dark.css',
      ],
      settings: {
        loginLogo: {
          src: 'themes/dark/images/login-logo-white.png',
          title: 'ForgeRock',
          alt: 'ForgeRock',
          height: '228px',
          width: '220px',
        },
      },
    },
  },
  mappings: [],
};
