<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, fmtDateTime, type DiagnosisResult, type MetricSample, type TimelineEvent } from '../api'

const emit = defineEmits<{ (e: 'navigate', tab: string, site?: string): void }>()

const loading = ref(true)
const overview = ref<any>(null)
const errMsg = ref('')

async function load() {
  loading.value = true
  errMsg.value = ''
  try {
    overview.value = await api('/api/v1/overview')
  } catch (e: any) {
    errMsg.value = e.message
  } finally {
    loading.value = false
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

function pillClass(sev: string) {
  if (sev === 'ok') return 'pill-ok'
  if (sev === 'warning') return 'pill-warn'
  if (sev === 'critical') return 'pill-critical'
  return 'pill-unknown'
}

onMounted(load)
</script>

<template>
  <div>
    <div class="row" style="margin-bottom: 14px;">
      <h2 style="margin: 0;">网关运行总览</h2>
      <div class="spacer"></div>
      <button v-if="overview?.demo_mode" class="btn btn-secondary" @click="seedDemo">注入三类赛时故障演示数据</button>
      <button class="btn" @click="load">刷新状态</button>
    </div>

    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <template v-if="overview">
      <div class="alert-banner" :class="overview.overall.severity === 'ok' ? 'alert-ok' : overview.overall.severity === 'warning' ? 'alert-warn' : overview.overall.severity === 'critical' ? 'alert-critical' : 'alert-unknown'">
        <div class="row">
          <span class="pill" :class="pillClass(overview.overall.severity)">{{ overview.overall.code }}</span>
          <strong>{{ overview.overall.summary_zh }}</strong>
        </div>
      </div>

      <div class="grid-4" style="margin-bottom: 16px;">
        <div class="card" style="margin-bottom: 0;">
          <div class="muted">当前活动赛事 Profile</div>
          <div style="font-size: 17px; font-weight: 700; margin-top: 6px;">
            {{ overview.active_profile?.id || '未激活' }}
          </div>
          <div class="muted" style="margin-top: 4px;">已存配置数：{{ overview.profile_count }}</div>
        </div>
        <div class="card" style="margin-bottom: 0;">
          <div class="muted">Hub 角色与主备路径 (#12)</div>
          <div style="font-size: 17px; font-weight: 700; margin-top: 6px;">
            角色: {{ overview.failover?.hub_role === 'backup' ? '自建备 Hub' : '自建主 Hub' }}
          </div>
          <div class="muted" style="margin-top: 4px;">
            模式: {{ overview.failover?.mode }} · 活动: {{ overview.failover?.active_path }}
          </div>
        </div>
        <div class="card" style="margin-bottom: 0;">
          <div class="muted">Root Agent 隔离守护进程</div>
          <div style="margin-top: 8px;">
            <span class="pill" :class="overview.agent_online ? 'pill-ok' : 'pill-warn'">
              {{ overview.agent_online ? 'ONLINE (Unix Socket SO_PEERCRED)' : 'OFFLINE / 离线预览模式' }}
            </span>
          </div>
        </div>
        <div class="card" style="margin-bottom: 0;">
          <div class="muted">已观测站点隧道数</div>
          <div style="font-size: 22px; font-weight: 700; margin-top: 4px;">{{ overview.sites?.length || 0 }}</div>
          <div class="muted">点击任意站点直达四层联动排障</div>
        </div>
      </div>

      <div class="card">
        <h3>站点实时四层健康矩阵</h3>
        <div v-if="!overview.sites?.length" class="muted">
          暂无采集数据。请在 Linux 生产机启动 <code>ipsecvpn agent serve</code>，或在演示模式下点击右上角「注入三类赛时故障演示数据」。
        </div>
        <table v-else class="table">
          <thead>
            <tr>
              <th>站点 ID</th>
              <th>L1 外层公网</th>
              <th>L2 IPsec SA</th>
              <th>L3 XFRM 速率/错误</th>
              <th>L4 端到端 UDP</th>
              <th>实时根因定界</th>
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
                  {{ row.sample.l1_outer_state === 1 ? `${row.sample.l1_outer_rtt_ms.toFixed(1)}ms` : row.sample.l1_outer_state === 0 ? 'DOWN' : row.sample.l1_mode }}
                </span>
                <div class="muted">丢包 {{ (row.sample.l1_outer_loss * 100).toFixed(0) }}%</div>
              </td>
              <td>
                <span class="pill" :class="row.sample.l2_ike_state === 1 && row.sample.l2_child_state === 1 ? 'pill-ok' : 'pill-critical'">
                  IKE:{{ row.sample.l2_ike_state === 1 ? 'UP' : 'DN' }} / CHILD:{{ row.sample.l2_child_state === 1 ? 'UP' : 'DN' }}
                </span>
              </td>
              <td>
                <div>RX {{ (row.sample.l3_rx_bps / 1e6).toFixed(2) }} / TX {{ (row.sample.l3_tx_bps / 1e6).toFixed(2) }} Mbps</div>
                <div class="muted">XFRM错误+{{ row.sample.l3_xfrm_err_delta }} / ACL丢包+{{ row.sample.l3_nft_drop_delta }}</div>
              </td>
              <td>
                <span class="pill" :class="row.sample.l4_udp_state === 1 ? 'pill-ok' : row.sample.l4_udp_state === 0 ? 'pill-critical' : 'pill-unknown'">
                  {{ row.sample.l4_udp_state === 1 ? `${row.sample.l4_udp_rtt_ms.toFixed(1)}ms` : row.sample.l4_udp_state === 0 ? 'DOWN' : 'UNKNOWN' }}
                </span>
              </td>
              <td>
                <span class="pill" :class="pillClass(row.diagnosis.severity)">{{ row.diagnosis.code }}</span>
              </td>
              <td>
                <button class="btn btn-secondary" @click="emit('navigate', 'diagnostics', row.sample.site_id)">四层联动排障</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <h3>最近实时事件流 (VICI / 探针 / 切备 / 变更)</h3>
        <table v-if="overview.recent_events?.length" class="table">
          <thead>
            <tr>
              <th>时间</th>
              <th>层级</th>
              <th>站点</th>
              <th>来源</th>
              <th>事件详情</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="ev in (overview.recent_events as TimelineEvent[]).slice().reverse().slice(0, 12)" :key="ev.id || ev.ts_ms">
              <td>{{ fmtDateTime(ev.ts_ms) }}</td>
              <td><span class="pill pill-info">{{ ev.layer }}</span></td>
              <td>{{ ev.site_id || '-' }}</td>
              <td>{{ ev.source }}</td>
              <td>{{ ev.title }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="muted">暂无事件记录。</div>
      </div>
    </template>
  </div>
</template>
