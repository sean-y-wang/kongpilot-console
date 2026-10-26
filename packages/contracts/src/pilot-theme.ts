import { theme as antTheme, type ThemeConfig } from 'antd';
import type { AppearanceMode } from './appearance-model';

export const PILOT_ACCENT = { light: '#1764D8', dark: '#79B0FF' } as const;
const fontFamily = "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif";

/** Solid navigation, three neutral text levels and restrained frosted cards. */
export const PILOT_THEME: ThemeConfig = {
  token: {
    colorPrimary: PILOT_ACCENT.light, colorInfo: PILOT_ACCENT.light,
    colorSuccess: '#157A52', colorWarning: '#8F5A00', colorError: '#C0353F',
    colorText: '#3D4756', colorTextSecondary: '#5A6475', colorTextTertiary: '#5A6475',
    colorTextDescription: '#5A6475', colorBorder: 'rgba(0,0,0,0.08)',
    colorBorderSecondary: 'rgba(0,0,0,0.04)', colorBgLayout: '#F5F8FC',
    colorBgContainer: '#FFFFFF', borderRadius: 8, borderRadiusLG: 8, fontSize: 14, lineHeight: 1.6, fontFamily,
  },
};

export function pilotTheme(mode: AppearanceMode): ThemeConfig {
  const dark = mode === 'dark';
  const primary = PILOT_ACCENT[mode];
  const hover = dark ? '#9CC4FF' : '#0F4FB3';
  const body = dark ? '#CBD2DE' : '#3D4756';
  const muted = dark ? '#A3ADBE' : '#5A6475';
  // WCAG AA: every text token >= 4.5:1 on canvas, panel and soft (docs/reference/accessibility.md).
  const status = dark ? { colorSuccess: '#6CC6A0', colorWarning: '#E0B25C', colorError: '#EF9AA2' } : {};
  // Light tinted notices: pale backgrounds, status-colored borders/icons, body-colored text.
  const notices = dark
    ? { colorInfoBg: '#162438', colorInfoBorder: '#2B4A75', colorSuccessBg: '#15271F', colorSuccessBorder: '#2A5A45', colorWarningBg: '#2A2316', colorWarningBorder: '#5E4A22', colorErrorBg: '#2D1B1F', colorErrorBorder: '#6A3640' }
    : { colorInfoBg: '#F0F6FF', colorInfoBorder: '#C9DDFB', colorSuccessBg: '#EFFAF4', colorSuccessBorder: '#BFE3CF', colorWarningBg: '#FFF8EB', colorWarningBorder: '#F2DAA8', colorErrorBg: '#FFF2F3', colorErrorBorder: '#F4C9CD' };
  const selected = dark ? '#1D2D47' : '#E6EFFD';
  const border = dark ? 'rgba(255,255,255,0.10)' : 'rgba(0,0,0,0.08)';
  const soft = dark ? '#1F2A3A' : '#EAF1FB';
  return {
    algorithm: dark ? antTheme.darkAlgorithm : antTheme.defaultAlgorithm,
    token: {
      ...PILOT_THEME.token, ...status, ...notices,
      colorPrimary: primary, colorPrimaryHover: hover, colorInfo: primary,
      colorText: body, colorTextSecondary: muted, colorTextTertiary: muted, colorTextDescription: muted,
      colorTextLightSolid: dark ? '#0B1320' : '#FFFFFF',
      colorBorder: border, colorBorderSecondary: dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.04)',
      colorBgLayout: dark ? '#111823' : '#F5F8FC', colorBgContainer: dark ? '#19222F' : '#FFFFFF',
      colorBgElevated: dark ? '#1F2A3A' : '#FFFFFF', colorLink: primary, colorLinkHover: hover,
    },
    components: {
      Layout: { headerBg: 'transparent', siderBg: dark ? '#19222F' : '#FFFFFF', bodyBg: 'transparent' },
      Menu: {
        itemBg: 'transparent', subMenuItemBg: 'transparent', itemBorderRadius: 8,
        itemSelectedBg: selected,
        itemSelectedColor: dark ? '#9CC4FF' : '#1459C2', itemColor: body,
        itemHoverBg: soft, itemDisabledColor: muted,
        darkItemBg: 'transparent', darkSubMenuItemBg: 'transparent', darkItemColor: body,
        darkItemSelectedBg: selected, darkItemSelectedColor: '#9CC4FF', darkItemHoverBg: soft,
      },
      Table: {
        headerBg: dark ? '#1F2A3A' : '#F2F6FC', headerColor: body,
        rowHoverBg: dark ? '#1F2B3C' : '#F7FAFE',
        borderColor: dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.04)', headerSplitColor: 'transparent',
      },
      Card: { boxShadowTertiary: '0 2px 12px rgba(0,0,0,0.06)' },
      Button: { primaryShadow: 'none', defaultShadow: 'none', primaryColor: dark ? '#0B1320' : '#FFFFFF' },
      Input: { activeBorderColor: primary, hoverBorderColor: hover, activeShadow: 'none' },
      Select: { activeBorderColor: primary, hoverBorderColor: hover, activeOutlineColor: 'transparent' },
      Tag: { defaultBg: soft, defaultColor: muted },
      Alert: { withDescriptionPadding: '14px 16px' },
    },
  };
}
