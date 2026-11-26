<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { api, fmtDateTime, type SyncedTimelineResponse } from '../api'
import SyncedFourLayerCharts from '../components/SyncedFourLayerCharts.vue'

const props = defineProps<{ initialSite?: string }>()

const site = ref(props.initialSite || 'ob-venue-1')
const siteOptions = ref<string[]>([])
const minutes = ref(60)
const timeline = ref<SyncedTimelineResponse | null>(null)
const errMsg = ref('')

async function loadSites() {
  try {
    const ov = await api<any>('/api/v1/overview')
    const ids: string[] = (ov.sites || []).map((r: any) => r.sample.site_id)
    siteOptions.value = Array.from(new Set(ids))
    if (siteOptions.value.length && !siteOptions.value.includes(site.value)) {
      site.value = siteOptions.value[0]
    }
  } catch {
    // ignore
  }
}

async function load() {
  errMsg.value = ''
  try {
    const q = new URLSearchParams({ site: site.value, minutes: String(minutes.value) })
    timeline.value = await api<SyncedTimelineResponse>(`/api/v1/diagnostics/timeline?${q}`)
  } catch (e: any) {
    errMsg.value = e.message
  }
}

function causeLabel(code: string) {
  const m: Record<string, string> = {
    VPN_HEALTHY_APP_SUSPECT: '链路正常',
    ISP_OUTER_DEGRADED: '公网线路异常',
    IPSEC_SA_EVENT: '隧道协商异常',
    TUNNEL_BLACKHOLE_OR_ASYMMETRIC: '隧道不通 / 路由异常',
    XFRM_CRYPTO_OR_MTU_DROP: '加解密 / MTU 异常',
    ACL_POLICY_DROP: '策略拦截',
    OBSERVATION_UNVERIFIED: '未检测'
  }
  return m[code] || code
}

watch(() => props.initialSite, (v) => {
  if (v) {
    site.value = v
    load()
  }
})

onMounted(async () => {
  await loadSites()
  await load()
})
</script>

<template>
  <div>
    <div class="row" style="margin-bottom: 14px;">
      <select v-if="siteOptions.length" v-model="site" class="select" style="width: 190px;" @change="load">
        <option v-for="s in siteOptions" :key="s" :value="s">{{ s }}</option>
      </select>
      <input v-else v-model="site" class="input" style="width: 190px;" placeholder="对端站点 ID" />

      <select v-model.number="minutes" class="select" style="width: 130px;" @change="load">
        <option :value="15">近 15 分钟</option>
        <option :value="60">近 1 小时</option>
        <option :value="360">近 6 小时</option>
        <option :value="1440">近 24 小时</option>
        <option :value="10080">近 7 天</option>
      </select>
      <button class="btn" @click="load">刷新</button>
      <div class="spacer"></div>
      <span class="muted">四张监控图按时间轴同步联动</span>
    </div>

    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <template v-if="timeline">
      <div
        class="alert-banner"
        :class="
          timeline.diagnosis.severity === 'ok'
            ? 'alert-ok'
            : timeline.diagnosis.severity === 'warning'
              ? 'alert-warn'
              : timeline.diagnosis.severity === 'critical'
                ? 'alert-critical'
                : 'alert-unknown'
        "
      >
        <div class="row">
          <span class="pill pill-info">{{ causeLabel(timeline.diagnosis.code) }}</span>
          <strong>{{ timeline.diagnosis.summary_zh }}</strong>
        </div>
        <div v-if="timeline.diagnosis.evidence?.length" class="row" style="margin-top: 8px;">
          <span v-for="e in timeline.diagnosis.evidence" :key="e" class="pill pill-unknown">{{ e }}</span>
        </div>
      </div>

      <SyncedFourLayerCharts :samples="timeline.samples" :events="timeline.events" />

      <div class="card">
        <h3>事件记录</h3>
        <table v-if="timeline.events.length" class="table">
          <thead>
            <tr>
              <th>时间</th>
              <th>事件</th>
              <th>级别</th>
              <th>说明</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="ev in timeline.events" :key="ev.id || ev.ts_ms">
              <td>{{ fmtDateTime(ev.ts_ms) }}</td>
              <td><code>{{ ev.category }}</code></td>
              <td>
                <span class="pill" :class="ev.severity === 'critical' ? 'pill-critical' : ev.severity === 'warning' ? 'pill-warn' : 'pill-info'">
                  {{ ev.severity === 'critical' ? '严重' : ev.severity === 'warning' ? '告警' : '通知' }}
                </span>
              </td>
              <td>{{ ev.title }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="muted">当前时间段内无异常事件。</div>
      </div>
    </template>
  </div>
</template>
