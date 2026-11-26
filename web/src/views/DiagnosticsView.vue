<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { api, fmtDateTime, type SyncedTimelineResponse } from '../api'
import SyncedFourLayerCharts from '../components/SyncedFourLayerCharts.vue'

const props = defineProps<{ initialSite?: string }>()

const site = ref(props.initialSite || 'ob-venue-1')
const minutes = ref(60)
const timeline = ref<SyncedTimelineResponse | null>(null)
const errMsg = ref('')

async function load() {
  errMsg.value = ''
  try {
    const q = new URLSearchParams({ site: site.value, minutes: String(minutes.value) })
    timeline.value = await api<SyncedTimelineResponse>(`/api/v1/diagnostics/timeline?${q}`)
  } catch (e: any) {
    errMsg.value = e.message
  }
}

watch(() => props.initialSite, (v) => {
  if (v) {
    site.value = v
    load()
  }
})

onMounted(load)
</script>

<template>
  <div>
    <div class="row" style="margin-bottom: 14px;">
      <h2 style="margin: 0;">四层同步排障时间轴（一眼定界 Ping / 隧道 / 内核 / 业务）</h2>
      <div class="spacer"></div>
      <input v-model="site" class="input" style="width: 180px;" placeholder="站点 ID (如 ob-venue-1)" />
      <select v-model.number="minutes" class="select" style="width: 130px;">
        <option :value="15">最近 15 分钟</option>
        <option :value="60">最近 1 小时</option>
        <option :value="360">最近 6 小时</option>
        <option :value="1440">最近 24 小时</option>
        <option :value="10080">最近 7 天</option>
      </select>
      <button class="btn" @click="load">查询联动曲线</button>
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
          <span class="pill pill-info">窗口根因定界</span>
          <strong>{{ timeline.diagnosis.code }}</strong>
          <span class="muted">故障层: {{ timeline.diagnosis.layer_fault }}</span>
        </div>
        <div style="margin-top: 6px;">{{ timeline.diagnosis.summary_zh }}</div>
        <div v-if="timeline.diagnosis.evidence?.length" class="row" style="margin-top: 8px;">
          <span v-for="e in timeline.diagnosis.evidence" :key="e" class="pill pill-unknown">{{ e }}</span>
        </div>
      </div>

      <SyncedFourLayerCharts :samples="timeline.samples" :events="timeline.events" />

      <div class="card">
        <h3>窗口内同步事件标注明细（与上方曲线竖线一一对应）</h3>
        <table v-if="timeline.events.length" class="table">
          <thead>
            <tr>
              <th>时间</th>
              <th>层级</th>
              <th>事件类型</th>
              <th>级别</th>
              <th>根因码</th>
              <th>说明</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="ev in timeline.events" :key="ev.id || ev.ts_ms">
              <td>{{ fmtDateTime(ev.ts_ms) }}</td>
              <td>{{ ev.layer }}</td>
              <td><code>{{ ev.category }}</code></td>
              <td>
                <span class="pill" :class="ev.severity === 'critical' ? 'pill-critical' : ev.severity === 'warning' ? 'pill-warn' : 'pill-info'">
                  {{ ev.severity }}
                </span>
              </td>
              <td><code>{{ ev.root_cause || '-' }}</code></td>
              <td>{{ ev.title }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="muted">所选窗口内无离散事件。鼠标滑动上方任意一层曲线，其余三层将同步定位到同一时刻。</div>
      </div>
    </template>
  </div>
</template>
