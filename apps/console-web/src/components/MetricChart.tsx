import { useEffect, useRef } from 'react';
import { Empty } from 'antd';
import * as echarts from 'echarts/core';
import { LineChart } from 'echarts/charts';
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import { hasMetricSamples, metricChartOption, type MetricPoint, type MetricUnit } from '../features/vitals-model';
import { usePilotAppearance } from '../../../../packages/contracts/src/PilotAppearance';

echarts.use([LineChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

export function MetricChart({ id, series, unit, stacked, unavailableReason }: { id: string; series: Array<{ name: string; points: MetricPoint[]; color?: string }>; unit: MetricUnit; stacked?: boolean; unavailableReason?: string }) {
  const { mode } = usePilotAppearance();
  const host = useRef<HTMLDivElement>(null);
  const available = series.some(row => hasMetricSamples(row.points));
  useEffect(() => {
    if (!host.current || !available) return;
    const chart = echarts.init(host.current, undefined, { renderer: 'canvas' });
    const colors: Record<string, string> = { '#3b6c99': '#9cbddd', '#7396b6': '#bccddd', '#a6b9ca': '#d8e1eb' };
    const option = metricChartOption(mode === 'dark' ? series.map(row => ({ ...row, color: colors[row.color ?? '#3b6c99'] ?? row.color })) : series, unit, stacked);
    const muted = mode === 'dark' ? '#a5afbd' : '#5e6878', border = mode === 'dark' ? '#354152' : '#e2e7ee';
    chart.setOption(option, { notMerge: true });
    // ECharts merges these display fields while retaining metric formatters and units.
    chart.setOption({ legend: { textStyle: { color: muted } },
      xAxis: { axisLabel: { color: muted }, axisLine: { lineStyle: { color: border } } },
      yAxis: { axisLabel: { color: muted }, nameTextStyle: { color: muted }, splitLine: { lineStyle: { color: border } } },
      tooltip: { backgroundColor: mode === 'dark' ? '#222d3b' : '#ffffff', borderColor: border, textStyle: { color: mode === 'dark' ? '#e6ebf3' : '#172236' } },
    });
    const resize = new ResizeObserver(() => chart.resize()); resize.observe(host.current);
    return () => { resize.disconnect(); chart.dispose(); };
  }, [series, unit, stacked, available, mode]);
  return <div className="metric-chart" data-testid={`vitals-chart-${id}`} data-available={available ? 'true' : 'false'}>
    {available ? <div ref={host} className="metric-chart-canvas" role="img" aria-label={`监控趋势 · ${id}`} /> : <div className="metric-chart-empty"><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={unavailableReason ?? '此范围暂无可用采样，等待数据通道采集。'} /></div>}
  </div>;
}
