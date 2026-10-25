import { PRODUCT_BRAND } from '../../../../packages/contracts/src/branding';

export { PRODUCT_BRAND };

export function BrandMark({ small = false }: { small?: boolean }) {
  return <span className={`portal-logo${small ? ' small' : ''}`}><img src="/kongpilot-logo.png" alt={`${PRODUCT_BRAND.name} 标识`} draggable={false} /></span>;
}
