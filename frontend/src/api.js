import axios from 'axios'

// Inside the Tauri app, the webview loads from a custom protocol
// (tauri://localhost / https://tauri.localhost), not from
// http://localhost:8000 — so a relative URL would resolve against the
// wrong origin and never reach the sidecar backend. `window.isTauri` is
// injected unconditionally by Tauri v2 into every webview (unlike
// `window.__TAURI__`, which only exists if `withGlobalTauri` is enabled
// in tauri.conf.json — it isn't here), so it's the reliable way to detect
// this context and force an absolute URL to the sidecar instead.
const BASE_URL = window.isTauri
  ? 'http://127.0.0.1:8000'
  : import.meta.env.PROD
    ? ''
    : import.meta.env.VITE_API_URL

const client = axios.create({
  baseURL: BASE_URL,
})

function unwrap(promise) {
  return promise.catch((err) => {
    const message =
      err.response?.data?.error ||
      err.message ||
      'Something went wrong talking to the server'
    throw new Error(message)
  })
}

export function uploadCsv(file) {
  const formData = new FormData()
  formData.append('file', file)
  return unwrap(
    client
      .post('/upload-csv', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      .then((res) => res.data),
  )
}

export function analyzeCsv(sessionId) {
  return unwrap(
    client.post(`/analyze/${sessionId}`).then((res) => res.data),
  )
}

export function confirmFields(sessionId, selectedFields) {
  return unwrap(
    client
      .post(`/confirm-fields/${sessionId}`, { selected_fields: selectedFields })
      .then((res) => res.data),
  )
}

// ---------------------------------------------------------------------------
// Security Onion data source. Same base URL and error handling as the CSV
// endpoints; the backend answers {"error": "..."} on every failure.
// ---------------------------------------------------------------------------

function soConnectionBody(host, port, username, password, verifySsl) {
  return {
    host: host.trim(),
    port: Number(port),
    username,
    password,
    verify_ssl: Boolean(verifySsl),
  }
}

export function testSOConnection(host, port, username, password, verifySsl) {
  return unwrap(
    client
      .post('/so/test-connection', soConnectionBody(host, port, username, password, verifySsl))
      .then((res) => res.data),
  )
}

export function listSOIndices(host, port, username, password, verifySsl) {
  return unwrap(
    client
      .post('/so/list-indices', soConnectionBody(host, port, username, password, verifySsl))
      .then((res) => res.data),
  )
}

export function querySOData(
  host,
  port,
  username,
  password,
  verifySsl,
  indexPattern,
  startTime,
  endTime,
  maxRows,
) {
  return unwrap(
    client
      .post('/so/query', {
        ...soConnectionBody(host, port, username, password, verifySsl),
        index_pattern: indexPattern,
        start_time: startTime,
        end_time: endTime,
        max_rows: Number(maxRows),
        time_field: '@timestamp',
      })
      .then((res) => res.data),
  )
}

export function previewSOFields(host, port, username, password, verifySsl, indexPattern, sampleSize = 1000) {
  return unwrap(
    client
      .post('/so/preview-fields', {
        ...soConnectionBody(host, port, username, password, verifySsl),
        index_pattern: indexPattern,
        sample_size: Number(sampleSize),
      })
      .then((res) => res.data),
  )
}
