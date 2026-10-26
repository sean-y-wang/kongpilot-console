import { theme as antTheme, type ThemeConfig } from 'antd';
import type { AppearanceMode } from './appearance-model';

export const PILOT_ACCENT = { light: '#4F5C83', dark: '#9CABCF' } as const;
const fontFamily = "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif";

/** Solid navigation, three neutral text levels and restrained frosted cards. */
export const PILOT_THEME: ThemeConfig = {
  token: {
    colorPrimary: PILOT_ACCENT.light, colorInfo: PILOT_ACCENT.light,
    colorSuccess: '#1E6B50', colorWarning: '#8A5A10', colorError: '#A3434B',
    colorText: '#3D4756', colorTextSecondary: '#5C6675', colorTextTertiary: '#5C6675',
    colorTextDescription: '#5C6675', colorBorder: 'rgba(0,0,0,0.08)',
    colorBorderSecondary: 'rgba(0,0,0,0.04)', colorBgLayout: '#F7F8FA',
    colorBgContainer: '#FFFFFF', borderRadius: 8, borderRadiusLG: 8, fontSize: 14, lineHeight: 1.6, fontFamily,
  },
};

export function pilotTheme(mode: AppearanceMode): ThemeConfig {
  const dark = mode === 'dark';
  const primary = PILOT_ACCENT[mode];
  const hover = dark ? '#B0BEDD' : '#3F4A6C';
  const body = dark ? '#CBD2DE' : '#3D4756';
  const muted = dark ? '#A3ADBE' : '#5C6675';
  // WCAG AA: every text token >= 4.5:1 on canvas, panel and soft (docs/reference/accessibility.md).
  const status = dark ? { colorSuccess: '#6CC6A0', colorWarning: '#E0B25C', colorError: '#E29AA1' } : {};
  const border = dark ? 'rgba(255,255,255,0.10)' : 'rgba(0,0,0,0.08)';
  const soft = dark ? '#222D3B' : '#EEF0F4';
  return {
    algorithm: dark ? antTheme.darkAlgorithm : antTheme.defaultAlgorithm,
    token: {
      ...PILOT_THEME.token, ...status,
      colorPrimary: primary, colorPrimaryHover: hover, colorInfo: primary,
      colorText: body, colorTextSecondary: muted, colorTextTertiary: muted, colorTextDescription: muted,
      colorTextLightSolid: dark ? '#121820' : '#FFFFFF',
      colorBorder: border, colorBorderSecondary: dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.04)',
      colorBgLayout: dark ? '#121820' : '#F7F8FA', colorBgContainer: dark ? '#1B2430' : '#FFFFFF',
      colorBgElevated: dark ? '#222D3B' : '#FFFFFF',
    },
    components: {
      Layout: { headerBg: 'transparent', siderBg: dark ? '#1B2430' : '#FFFFFF', bodyBg: 'transparent' },
      Menu: {
        itemBg: 'transparent', subMenuItemBg: 'transparent', itemBorderRadius: 8,
        itemSelectedBg: dark ? 'rgba(156,171,207,0.10)' : 'rgba(89,102,141,0.06)',
        itemSelectedColor: dark ? '#E6EBF3' : '#1D2129', itemColor: body,
        itemHoverBg: soft, itemDisabledColor: muted,
        darkItemBg: 'transparent', darkSubMenuItemBg: 'transparent', darkItemColor: body,
        darkItemSelectedBg: 'rgba(156,171,207,0.10)', darkItemSelectedColor: '#E6EBF3', darkItemHoverBg: soft,
      },
      Table: {
        headerBg: dark ? '#222D3B' : 'rgba(247,248,250,0.70)', headerColor: body,
        rowHoverBg: dark ? 'rgba(156,171,207,0.06)' : 'rgba(89,102,141,0.025)',
        borderColor: dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.04)', headerSplitColor: 'transparent',
      },
      Card: { boxShadowTertiary: '0 2px 12px rgba(0,0,0,0.06)' },
      Button: { primaryShadow: 'none', defaultShadow: 'none', primaryColor: dark ? '#121820' : '#FFFFFF' },
      Input: { activeBorderColor: primary, hoverBorderColor: hover, activeShadow: 'none' },
      Select: { activeBorderColor: primary, hoverBorderColor: hover, activeOutlineColor: 'transparent' },
      Tag: { defaultBg: soft, defaultColor: muted },
    },
  };
}
