import content from './faq-content.json';
import type { Lang } from './i18n';

export interface FaqSection {
  id: string;
  title: string;
  items: string[];
}

export const faqSections: Record<Lang, FaqSection[]> = {
  ru: content.ru,
  en: content.en,
};
