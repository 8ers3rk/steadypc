import { useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import { faqSections } from '../faq';
import type { Lang } from '../i18n';

interface FaqDialogProps {
  lang: Lang;
  t: (key: string) => string;
  onClose: () => void;
}

export function FaqDialog({ lang, t, onClose }: FaqDialogProps) {
  const dialogRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeRef.current?.focus();

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== 'Tab' || !dialogRef.current) return;

      const focusable = Array.from(
        dialogRef.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), summary, [href], input, [tabindex]:not([tabindex="-1"])',
        ),
      );
      if (!focusable.length) return;

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      previous?.focus();
    };
  }, [onClose]);

  return (
    <div
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        ref={dialogRef}
        className="modal faq-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="faq-title"
      >
        <header className="faq-header">
          <div>
            <h2 id="faq-title">{t('faq.title')}</h2>
            <p className="muted">{t('faq.subtitle')}</p>
          </div>
          <button
            ref={closeRef}
            type="button"
            className="icon-button"
            onClick={onClose}
            aria-label={t('common.close')}
            title={t('common.close')}
          >
            <X size={16} />
          </button>
        </header>

        <div className="faq-content">
          {faqSections[lang].map((section) => (
            <details className="faq-section" key={section.id} open={section.id === 'about'}>
              <summary>{section.title}</summary>
              <ul>
                {section.items.map((item, index) => (
                  <li key={`${section.id}-${index}`}>{item}</li>
                ))}
              </ul>
            </details>
          ))}
        </div>

        <div className="modal-actions">
          <button type="button" className="button" onClick={onClose}>
            {t('faq.close')}
          </button>
        </div>
      </section>
    </div>
  );
}
