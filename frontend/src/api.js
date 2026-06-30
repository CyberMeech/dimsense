import axios from 'axios'

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
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
