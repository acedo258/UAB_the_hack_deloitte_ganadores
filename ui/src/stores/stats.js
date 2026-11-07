import { defineStore } from 'pinia'
import { api } from '../api'

export const useStats = defineStore('stats', {
  state: () => ({ data: null }),
  actions: { async load() { this.data = await api.stats() } },
})
