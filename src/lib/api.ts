import type { SteadyPCApi } from '../types';

export function api(): SteadyPCApi {
  if (!window.steadypc) {
    throw new Error('SteadyPC API недоступно. Приложение должно быть запущено в Electron.');
  }
  return window.steadypc;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 Б';
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / Math.pow(1024, index);
  const rendered = Number.isInteger(value) ? String(value) : value.toFixed(1);
  return `${rendered} ${units[index]}`;
}

export function formatDate(value: string, lang: 'ru' | 'en'): string {
  try {
    return new Intl.DateTimeFormat(lang === 'ru' ? 'ru-RU' : 'en-US', {
      day: '2-digit',
      month: 'short',
      hour: '2-digit',
      minute: '2-digit',
    }).format(new Date(value));
  } catch (error) {
    return value;
  }
}
