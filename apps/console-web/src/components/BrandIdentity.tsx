import { PRODUCT_BRAND } from '../../../../packages/contracts/src/branding';

export { PRODUCT_BRAND };

export function BrandMark({ large = false }: { large?: boolean }) {
  return <span className={`brand-mark${large ? ' large' : ''}`}><img src="/kongpilot-logo.png" alt={`${PRODUCT_BRAND.name} 标识`} draggable={false} /></span>;
}
