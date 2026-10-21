export type ModuleStatus =
  | 'AVAILABLE'
  | 'CONFIRMED_EMPTY'
  | 'NOT_PROVIDED'
  | 'PARSING_INCOMPLETE'
  | 'REQUEST_FAILED';

export interface ModuleStateResult {
  status: ModuleStatus;
  badgeText: string;
  isAvailable: boolean;
  isConfirmedEmpty: boolean;
  isNotProvided: boolean;
  isParsingIncomplete: boolean;
  isError: boolean;
  errorMessage?: string;
  count: number;
}

export function getModuleState(params: {
  isError?: boolean;
  error?: unknown;
  items?: any[] | object | null | undefined;
  sectionKey: string;
  parsingStatus?: string | null;
  parsingWarnings?: string[] | null;
  provenance?: { providedSections?: string[]; [key: string]: any } | null;
}): ModuleStateResult {
  const { isError, error, items, sectionKey, parsingStatus, parsingWarnings, provenance } = params;

  if (isError) {
    return {
      status: 'REQUEST_FAILED',
      badgeText: 'Error',
      isAvailable: false,
      isConfirmedEmpty: false,
      isNotProvided: false,
      isParsingIncomplete: false,
      isError: true,
      errorMessage: error instanceof Error ? error.message : 'Failed to load module data from API.',
      count: 0,
    };
  }

  const isArray = Array.isArray(items);
  const count = isArray ? (items as any[]).length : items ? 1 : 0;
  const providedSections: string[] = provenance?.providedSections || [];
  const isExplicitlyProvided = providedSections.includes(sectionKey);

  if (count > 0) {
    return {
      status: 'AVAILABLE',
      badgeText: `${count} ${count === 1 ? 'item' : 'items'}`,
      isAvailable: true,
      isConfirmedEmpty: false,
      isNotProvided: false,
      isParsingIncomplete: false,
      isError: false,
      count,
    };
  }

  if (isExplicitlyProvided) {
    const hasSectionWarning = parsingWarnings && parsingWarnings.some(w => w.toLowerCase().includes(sectionKey.toLowerCase()));
    if (parsingStatus === 'PARTIAL' && hasSectionWarning) {
      return {
        status: 'PARSING_INCOMPLETE',
        badgeText: 'Parsing Incomplete',
        isAvailable: false,
        isConfirmedEmpty: false,
        isNotProvided: false,
        isParsingIncomplete: true,
        isError: false,
        count: 0,
      };
    }

    return {
      status: 'CONFIRMED_EMPTY',
      badgeText: '0 items (Clean)',
      isAvailable: false,
      isConfirmedEmpty: true,
      isNotProvided: false,
      isParsingIncomplete: false,
      isError: false,
      count: 0,
    };
  }

  return {
    status: 'NOT_PROVIDED',
    badgeText: 'Not Provided',
    isAvailable: false,
    isConfirmedEmpty: false,
    isNotProvided: true,
    isParsingIncomplete: false,
    isError: false,
    count: 0,
  };
}
