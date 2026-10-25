import { BadGatewayException, ConflictException } from '@nestjs/common';
/** Shared by every provider call in one overview, including consumer and gauges. */
export class MetricsQueryBudget {
  private calls = 0; private bytes = 0; private series = 0; private points = 0;
  constructor(private readonly limits = { calls: 18, bytes: 8 * 1024 * 1024, series: 64, points: 51200 }) {}
  beginCall(): number {
    if (++this.calls > this.limits.calls || this.bytes >= this.limits.bytes) this.exhausted();
    return this.limits.bytes - this.bytes;
  }
  chargeResponse(bytes: number): void {
    if (!Number.isInteger(bytes) || bytes < 0 || (this.bytes += bytes) > this.limits.bytes) this.exhausted();
  }
  chargeSeries(points: number): void {
    if (!Number.isInteger(points) || points < 0 || points > 800 || ++this.series > this.limits.series || (this.points += points) > this.limits.points) this.exhausted();
  }
  publicResponse(value: unknown): void {
    if (Buffer.byteLength(JSON.stringify(value)) > 2 * 1024 * 1024) throw new BadGatewayException({ code: 'METRICS_PUBLIC_RESPONSE_TOO_LARGE', message: '监控响应超过安全预算' });
  }
  snapshot() { return { calls: this.calls, bytes: this.bytes, series: this.series, points: this.points }; }
  private exhausted(): never { throw new ConflictException({ code: 'METRICS_QUERY_BUDGET_EXHAUSTED', message: '监控查询超过调用、样本或响应预算，请缩小范围' }); }
}
