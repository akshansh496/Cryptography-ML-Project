import api from './api'

export interface TopFeature {
  name: string
  description: string
  contribution: number
  importance?: number
  feature?: string
}

export interface Scan {
  id: string
  filename: string
  fileSize: number
  sha256: string
  verdict: 'benign' | 'malicious'
  probability: number
  riskScore: number
  riskLevel: 'Low' | 'Medium' | 'High'
  explanation: TopFeature[] | null
  modelVersion: string
  createdAt: string
  duplicate?: boolean
}

export interface ScansListResponse {
  items: Scan[]
  page: number
  limit: number
  total: number
  totalPages: number
}

export type SortBy = 'createdAt' | 'riskScore'
export type SortOrder = 'asc' | 'desc'

export async function uploadFile(file: File, onProgress?: (pct: number) => void): Promise<Scan> {
  const form = new FormData()
  form.append('file', file)

  const { data } = await api.post<Scan>('/api/scans', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (e) => {
      if (onProgress && e.total) onProgress(Math.round((e.loaded / e.total) * 100))
    },
  })
  return data
}

export async function getScans(params: {
  page?: number
  limit?: number
  sortBy?: SortBy
  order?: SortOrder
}): Promise<ScansListResponse> {
  const { data } = await api.get<ScansListResponse>('/api/scans', { params })
  return data
}

export async function getScan(id: string): Promise<Scan> {
  const { data } = await api.get<Scan>(`/api/scans/${id}`)
  return data
}

export async function downloadFile(id: string, filename: string): Promise<void> {
  const response = await api.get(`/api/scans/${id}/download`, {
    responseType: 'blob',
  })

  // Extract filename from Content-Disposition header if present
  const disposition = response.headers['content-disposition'] as string | undefined
  let downloadName = filename
  if (disposition) {
    const match = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/)
    if (match) {
      try {
        downloadName = decodeURIComponent(match[1].replace(/['"]/g, ''))
      } catch {
        downloadName = filename
      }
    }
  }

  const url = URL.createObjectURL(new Blob([response.data]))
  const a = document.createElement('a')
  a.href = url
  a.download = downloadName
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export async function deleteScan(id: string): Promise<void> {
  await api.delete(`/api/scans/${id}`)
}
