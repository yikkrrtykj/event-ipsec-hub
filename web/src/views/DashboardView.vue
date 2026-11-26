<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, fmtDateTime, type DiagnosisResult, type MetricSample, type TimelineEvent } from '../api'

const emit = defineEmits<{ (e: 'navigate', tab: string, site?: string): void }>()

const overview = ref<any>(null)
const errMsg = ref('')

async function load() {
  errMsg.value = ''
  try {
    overview.value = await api('/api/v1/overview')
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function seedDemo() {
  try {
    await api('/api/v1/diagnostics/seed-demo', { method: 'POST' })
    await load()
  } catch (e: any) {
    errMsg.value = e.message
  }
}

function causeLabel(code: string) {
  const m: Record<string, string> = {
    VPN_HEALTHY_APP_SUSPECT: '正常',
    ISP_OUTER_DEGRADED: '公网线路异常',
    IPSEC_SA_EVENT: '隧道异常',
    TUNNEL_BLACKHOLE_OR_ASYMMETRIC: '路由/黑洞异常',
    XFRM_CRYPTO_OR_MTU_DROP: '内核/MTU 异常',
    ACL_POLICY_DROP: '策略拦截',
    OBSERVATION_UNVERIFIED: '未检测'
  }
  return m[code] || code
}

function pillClass(sev: string) {
  if (sev === 'ok') return 'pill-ok'
  if (sev === 'warning') return 'pill-warn'
  if (sev === 'critical') return 'pill-critical'
  return 'pill-unknown'
}

function modeText(mode: string) {
  const m: Record<string, string> = {
    PRIMARY_ACTIVE: '主路运行',
    BACKUP_LOCKED: '备路锁定',
    PRIMARY_RECOVERY_READY: '主路就绪待回切',
    MANUAL_STOP: '人工接管'
  }
  return m[mode] || mode
}

onMounted(load)
</script>

<template>
  <div>
    <div class="row" style="margin-bottom: 14px;">
      <div class="spacer"></div>
      <button v-if="overview?.demo_mode" class="btn btn-secondary" @click="seedDemo">生成示例监控数据</button>
      <button class="btn" @click="load">刷新</button>
    </div>

    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <template v-if="overview">
      <div class="alert-banner" :class="overview.overall.severity === 'ok' ? 'alert-ok' : overview.overall.severity === 'warning' ? 'alert-warn' : overview.overall.severity === 'critical' ? 'alert-critical' : 'alert-unknown'">
        <div class="row">
          <span class="pill" :class="pillClass(overview.overall.severity)">{{ causeLabel(overview.overall.code) }}</span>
          <span>{{ overview.overall.summary_zh }}</span>
        </div>
      </div>

      <div class="grid-4" style="margin-bottom: 16px;">
        <div class="card" style="margin-bottom: 0;">
          <div class="muted">当前配置</div>
          <div style="font-size: 16px; font-weight: 700; margin-top: 6px;">
            {{ overview.active_profile?.id || '未启用' }}
          </div>
          <div class="muted" style="margin-top: 4px;">已保存 {{ overview.profile_count }} 份配置</div>
        </div>
        <div class="card" style="margin-bottom: 0;">
          <div class="muted">主备状态</div>
          <div style="font-size: 16px; font-weight: 700; margin-top: 6px;">
            {{ modeText(overview.failover?.mode) }}
          </div>
          <div class="muted" style="margin-top: 4px;">
            当前网关：{{ overview.failover?.hub_role === 'backup' ? '备网关' : '主网关' }} · 活动路径：{{ overview.failover?.active_path === 'backup' ? '备路' : '主路' }}
          </div>
        </div>
        <div class="card" style="margin-bottom: 0;">
          <div class="muted">网关服务</div>
          <div style="margin-top: 8px;">
            <span class="pill" :class="overview.agent_online ? 'pill-ok' : 'pill-warn'">
              {{ overview.agent_online ? '运行中' : '未连接' }}
            </span>
          </div>
        </div>
        <div class="card" style="margin-bottom: 0;">
          <div class="muted">已监控通道</div>
          <div style="font-size: 22px; font-weight: 700; margin-top: 4px;">{{ overview.sites?.length || 0 }}</div>
        </div>
      </div>

      <div class="card">
        <h3>VPN 通道列表</h3>
        <div v-if="!overview.sites?.length" class="muted">
          暂无通道监控数据。
        </div>
        <table v-else class="table">
          <thead>
            <tr>
              <th>对端站点</th>
              <th>外层链路</th>
              <th>隧道状态</th>
              <th>实时带宽</th>
              <th>内网探针</th>
              <th>状态判定</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in overview.sites as Array<{ sample: MetricSample; diagnosis: DiagnosisResult }>" :key="row.sample.site_id">
              <td>
                <strong>{{ row.sample.site_id }}</strong>
                <div class="muted">{{ row.sample.isp_label }}</div>
              </td>
              <td>
                <span class="pill" :class="row.sample.l1_outer_state === 1 ? 'pill-ok' : row.sample.l1_outer_state === 0 ? 'pill-critical' : 'pill-unknown'">
                  {{ row.sample.l1_outer_state === 1 ? `${row.sample.l1_outer_rtt_ms.toFixed(1)} ms` : row.sample.l1_outer_state === 0 ? '中断' : '未启用' }}
                </span>
                <div class="muted">丢包 {{ (row.sample.l1_outer_loss * 100).toFixed(0) }}%</div>
              </td>
              <td>
                <span class="pill" :class="row.sample.l2_ike_state === 1 && row.sample.l2_child_state === 1 ? 'pill-ok' : 'pill-critical'">
                  {{ row.sample.l2_ike_state === 1 && row.sample.l2_child_state === 1 ? '已连通' : '已断开' }}
                </span>
              </td>
              <td>
                <div>入 {{ (row.sample.l3_rx_bps / 1e6).toFixed(2) }} / 出 {{ (row.sample.l3_tx_bps / 1e6).toFixed(2) }} Mbps</div>
                <div class="muted">异常计数 +{{ row.sample.l3_xfrm_err_delta + row.sample.l3_nft_drop_delta }}</div>
              </td>
              <td>
                <span class="pill" :class="row.sample.l4_udp_state === 1 ? 'pill-ok' : row.sample.l4_udp_state === 0 ? 'pill-critical' : 'pill-unknown'">
                  {{ row.sample.l4_udp_state === 1 ? `${row.sample.l4_udp_rtt_ms.toFixed(1)} ms` : row.sample.l4_udp_state === 0 ? '不通' : '未检测' }}
                </span>
              </td>
              <td>
                <span class="pill" :class="pillClass(row.diagnosis.severity)">{{ causeLabel(row.diagnosis.code) }}</span>
              </td>
              <td>
                <button class="btn btn-secondary" @click="emit('navigate', 'diagnostics', row.sample.site_id)">查看监控</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <h3>近期事件</h3>
        <table v-if="overview.recent_events?.length" class="table">
          <thead>
            <tr>
              <th>时间</th>
              <th>类型</th>
              <th>站点</th>
              <th>来源</th>
              <th>内容</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="ev in (overview.recent_events as TimelineEvent[]).slice().reverse().slice(0, 12)" :key="ev.id || ev.ts_ms">
              <td>{{ fmtDateTime(ev.ts_ms) }}</td>
              <td><code>{{ ev.category }}</code></td>
              <td>{{ ev.site_id || '-' }}</td>
              <td>{{ ev.source === 'self_hosted_hub' ? '自建网关' : ev.source }}</td>
              <td>{{ ev.title }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="muted">暂无事件记录。</div>
      </div>
    </template>
  </div>
</template>
