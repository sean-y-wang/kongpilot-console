import React, { type HTMLAttributes, type ReactNode } from 'react';

// Local decorative outline icons; no font download or remote sprites.
const paths = {
  overview: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
  cluster: <><rect x="3" y="3" width="18" height="7" rx="2" /><rect x="3" y="14" width="18" height="7" rx="2" /><path d="M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6" /></>,
  database: <><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" /></>,
  service: <path d="m12 3 9 5-9 5-9-5 9-5ZM3 12l9 5 9-5M3 16l9 5 9-5" />,
  route: <><circle cx="12" cy="4" r="2" /><circle cx="5" cy="20" r="2" /><circle cx="19" cy="20" r="2" /><path d="M12 6v5M5 18v-3a4 4 0 0 1 4-4h6a4 4 0 0 1 4 4v3" /></>,
  users: <><circle cx="9" cy="7" r="3" /><path d="M3 21v-2a6 6 0 0 1 12 0v2M16 4a3 3 0 0 1 0 6M18 15a5 5 0 0 1 3 4v2" /></>,
  plugin: <path d="M8 3H4a1 1 0 0 0-1 1v4h2a3 3 0 1 1 0 6H3v6a1 1 0 0 0 1 1h5v-2a3 3 0 1 1 6 0v2h5a1 1 0 0 0 1-1v-6h-2a3 3 0 1 1 0-6h2V4a1 1 0 0 0-1-1h-6V2a3 3 0 1 0-6 0v1Z" />,
  upstream: <><path d="M6 17a5 5 0 0 1-1-10 7 7 0 0 1 13-1 5.5 5.5 0 0 1 1 11" /><rect x="6" y="14" width="12" height="7" rx="2" /><path d="M9 17.5h.01M12 17.5h3" /></>,
  certificate: <path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3ZM8 12l3 3 5-6" />,
  key: <><circle cx="8" cy="8" r="5" /><path d="m12 12 9 9M16 16l3-3M19 19l3-3" /></>,
  globe: <><circle cx="12" cy="12" r="9" /><ellipse cx="12" cy="12" rx="4" ry="9" /><path d="M3 12h18" /></>,
  trash: <path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7" />,
  chart: <path d="M4 21V10M12 21V3M20 21v-7" />,
  approval: <><rect x="5" y="4" width="14" height="17" rx="2" /><path d="M9 4V2h6v2M8 13l3 3 5-6" /></>,
  audit: <path d="M14 2H5a1 1 0 0 0-1 1v18a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V8l-6-6ZM14 2v6h6M8 12h8M8 16h8" />,
  event: <path d="m13 2-9 12h7l-1 8 10-13h-7l0-7Z" />,
  bell: <path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" />,
  snapshot: <><circle cx="12" cy="12" r="9" /><path d="M12 6v6l4 2" /></>,
  exchange: <path d="M4 8h15m-4-4 4 4-4 4M20 16H5m4-4-4 4 4 4" />,
  git: <><circle cx="6" cy="4" r="2" /><circle cx="6" cy="20" r="2" /><circle cx="18" cy="8" r="2" /><path d="M6 6v12M8 16h3a7 7 0 0 0 7-6" /></>,
  toolbox: <path d="M21 7a6 6 0 0 1-8 6l-8 8-3-3 8-8a6 6 0 0 1 6-8l-3 4 4 4 4-3Z" />,
  settings: <><path d="m9 3 1-1h4l1 1v2l2 1 2-1 2 3v2l-2 1v2l2 1v2l-2 3-2-1-2 1v2l-1 1h-4l-1-1v-2l-2-1-2 1-2-3v-2l2-1v-2l-2-1V8l2-3 2 1 2-1V3Z" /><circle cx="12" cy="12" r="3" /></>,
  plus: <path d="M12 5v14M5 12h14" />,
  edit: <path d="m15 4 5 5-10 10-6 1 1-6L15 4ZM13 6l5 5" />,
  reload: <path d="M20 7v5h-5M4 17v-5h5M5 8a8 8 0 0 1 13-3l2 2M19 16a8 8 0 0 1-13 3l-2-2" />,
  search: <><circle cx="10.5" cy="10.5" r="7" /><path d="m16 16 5 5" /></>,
  'arrow-right': <path d="M4 12h16m-6-6 6 6-6 6" />,
  'check-circle': <><circle cx="12" cy="12" r="9" /><path d="m8 12 3 3 5-6" /></>,
  'chevron-up': <path d="m6 15 6-6 6 6" />,
  'chevron-down': <path d="m6 9 6 6 6-6" />,
  'chevron-left': <path d="m15 6-6 6 6 6" />,
  'chevron-right': <path d="m9 6 6 6-6 6" />,
  menu: <path d="M4 6h16M4 12h16M4 18h16" />,
  close: <path d="m6 6 12 12M6 18 18 6" />,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M5 19l1.5-1.5M17.5 6.5 19 5" /></>,
  moon: <path d="M21 13a9 9 0 0 1-10-10 9 9 0 1 0 10 10Z" />,
} satisfies Record<string, ReactNode>;

export function PilotIcon({ name, className = '', ...props }: HTMLAttributes<HTMLSpanElement> & { name: keyof typeof paths }) {
  return <span {...props} className={`anticon pilot-icon ${className}`} aria-hidden="true"><svg width="1em" height="1em" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" focusable="false">{paths[name]}</svg></span>;
}
