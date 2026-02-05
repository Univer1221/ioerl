import { Component, OnInit, inject, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { NgSelectModule } from '@ng-select/ng-select';
import { environment } from '../../../../environments/environment';
import { EmailService } from '../../../services/email';
import { ApplicationService } from '../../../services/application';
import { SecureStorageService } from '../../../services/secure-storage.service';
import { PaginationComponent } from '../../../shared/components/pagination/pagination';
import { EmailDetailModalComponent } from '../detail/email-detail-modal';
import { Email, EmailPost } from '../../../models/email.model';
import { Application } from '../../../models/application.model';
import { ToastrService } from 'ngx-toastr';
import { switchMap, tap, catchError, debounceTime, distinctUntilChanged } from 'rxjs/operators';
import { of, Subject, firstValueFrom } from 'rxjs';
import { EMAIL_MESSAGES, MESSAGE_TITLES } from '../../../shared/constants/messages';

@Component({
  selector: 'app-email-list',
  standalone: true,
  imports: [CommonModule, PaginationComponent, FormsModule, NgSelectModule, EmailDetailModalComponent],
  templateUrl: './email-list.html',
  styleUrl: './email-list.scss',
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class EmailListComponent implements OnInit {
  private emailService = inject(EmailService);
  private applicationService = inject(ApplicationService);
  private secureStorage = inject(SecureStorageService);
  private toastr = inject(ToastrService);
  private route = inject(ActivatedRoute);
    private cdr = inject(ChangeDetectorRef);

  emailList: Email[] = [];
  applicationList: Application[] = [];
  currentPage: number = 1;
  pageSize: number = 5;
  count: number = 0;
  searchTerm: string = '';
  selectedAppName: string = '';
  viewMode: 'list' | 'card' = 'list';

  // Test Email Form
  showTestForm: boolean = false;
  isSending: boolean = false;
  isDirectAccess: boolean = false; // True when user navigates directly without appId query param
  useTPInternalConfig: boolean = false; // When true, use TP Internal email config instead of app
  emailData: EmailPost = {
    subject: '',
    body: '',
    isHtml: false,
    toRecipients: '',
    ccRecipients: '',
    appId: null,
    appPassword: '',
    smtpUserEmail: '',
    useTPAssist: false
  };
  selectedFiles: File[] = [];

  // TPAssist Preview
  isEnhancing: boolean = false;
  tpAssistPreview: string = '';
  showTPAssistPreview: boolean = false;

  // Email Detail Modal
  showEmailDetailModal: boolean = false;
  selectedEmailId: string | null = null;

  // Debounced search
  private searchSubject = new Subject<string>();

  // To/CC Recipients search
  toRecipientsSearchInput$ = new Subject<string>();
  toRecipientsLoading: boolean = false;
  adUsersForRecipients: any[] = [];

  ccRecipientsSearchInput$ = new Subject<string>();
  ccRecipientsLoading: boolean = false;
  adUsersForCCRecipients: any[] = [];

  async ngOnInit(): Promise<void> {
    // Setup debounced search first
    this.searchSubject.pipe(
      debounceTime(500),
      distinctUntilChanged()
    ).subscribe(() => {
      this.onSearch();
    });

    // Setup To/CC recipients search
    this.setupRecipientsSearch();

    // Check for appId in query params FIRST (before loading data)
    // This ensures emailData.appId is set when applications load
    const params = this.route.snapshot.queryParams;
    if (params['appId']) {
      this.emailData.appId = +params['appId'];
      this.showTestForm = true;
      this.isDirectAccess = false; // Coming from app registration flow
    } else {
      this.isDirectAccess = true; // User navigated directly to this page
    }

    // Now load data
    await this.loadEmails();
    await this.loadApplications();

    // Subscribe to queryParams for subsequent changes (navigation while on same page)
    this.route.queryParams.subscribe(queryParams => {
      const appId = queryParams['appId'];
      if (appId && this.emailData.appId !== +appId) {
        this.emailData.appId = +appId;
        this.showTestForm = true;
        
        if (this.applicationList.length > 0) {
          this.onApplicationChange();
        }
        this.cdr.markForCheck();
      }
    });
  }

  private setupRecipientsSearch(): void {
    // Removed - using (search) event in template instead
  }

  onToRecipientsSearch(term: string): void {
    if (!term || term.length < 2) {
      this.adUsersForRecipients = [];
      this.toRecipientsLoading = false;
      this.cdr.markForCheck();
      return;
    }

    this.toRecipientsLoading = true;
    this.cdr.markForCheck();
    this.applicationService.searchADUsers(term).pipe(
      catchError(() => {
        this.toRecipientsLoading = false;
        this.cdr.markForCheck();
        return of(null);
      })
    ).subscribe(response => {
      this.toRecipientsLoading = false;
      if (response && response.users) {
        this.adUsersForRecipients = response.users.filter((u: any) => u.mail);
      }
      this.cdr.markForCheck();
    });
  }

  onCCRecipientsSearch(term: string): void {
    if (!term || term.length < 2) {
      this.adUsersForCCRecipients = [];
      this.ccRecipientsLoading = false;
      this.cdr.markForCheck();
      return;
    }

    this.ccRecipientsLoading = true;
    this.cdr.markForCheck();
    this.applicationService.searchADUsers(term).pipe(
      catchError(() => {
        this.ccRecipientsLoading = false;
        this.cdr.markForCheck();
        return of(null);
      })
    ).subscribe(response => {
      this.ccRecipientsLoading = false;
      if (response && response.users) {
        this.adUsersForCCRecipients = response.users.filter((u: any) => u.mail);
      }
      this.cdr.markForCheck();
    });
  }

  compareRecipientEmails(a: any, b: any): boolean {
    if (!a || !b) return a === b;
    return a?.mail === b?.mail || a === b;
  }

  async loadEmails(): Promise<void> {
    try {
      const response: any = await firstValueFrom(
        this.emailService.getEmails(this.currentPage, this.pageSize, this.searchTerm, this.selectedAppName)
      );
      if (response && (response.data || response.resultData)) {
        const emails = response.data || (response.resultData && response.resultData.length > 0 ? response.resultData : []);
        this.emailList = emails;
        this.count = response.totalRecords || 0;
      }
      // FIX: Trigger change detection for OnPush strategy
      this.cdr.markForCheck();
    } catch (error) {
      this.cdr.markForCheck();
    }
  }

  async onSearch(): Promise<void> {
    this.currentPage = 1;
    await this.loadEmails();
  }

  // Debounced search trigger
  onSearchInput(term: string) {
    this.searchTerm = term;
    this.searchSubject.next(term);
  }

  async onAppFilterChange(): Promise<void> {
    this.currentPage = 1;
    await this.loadEmails();
  }

  async loadApplications(): Promise<void> {
    try {
      const response: any = await firstValueFrom(this.applicationService.getApplications(1, 1000));
      console.log('[DEBUG] loadApplications response:', response);
      if (response && (response.data || response.resultData)) {
        const applications = response.data || (response.resultData && response.resultData.length > 0 ? response.resultData : []);
        this.applicationList = applications;
        
        console.log('[DEBUG] applicationList loaded:', this.applicationList);
        // If appId was set via query params, trigger application change to load SMTP user email
        if (this.emailData.appId) {
          console.log('[DEBUG] appId from query params:', this.emailData.appId);
          this.onApplicationChange();
        }
      }
      // FIX: Trigger change detection
      this.cdr.markForCheck();
    } catch (error) {
      this.cdr.markForCheck();
    }
  }

  async onPageChange(page: number): Promise<void> {
    this.currentPage = page;
    await this.loadEmails();
  }

  toggleTestForm() {
    this.showTestForm = !this.showTestForm;
  }

  onFileChange(event: any) {
    if (event.target.files && event.target.files.length > 0) {
      this.selectedFiles = Array.from(event.target.files);
    }
  }

  // Handle TP Internal Config toggle change
  onTPInternalToggle() {
    if (this.useTPInternalConfig) {
      // Clear app-specific fields when using TP Internal
      this.emailData.appId = null;
      this.emailData.smtpUserEmail = '';
      this.emailData.appPassword = '';
    }
    this.cdr.markForCheck();
  }

  onApplicationChange() {
    const appId = this.emailData.appId;
    console.log('[DEBUG] onApplicationChange called, appId:', appId);
    console.log('[DEBUG] applicationList:', this.applicationList);
    
    if (appId) {
      const selectedApp = this.applicationList.find(app => app.id.toString() === appId.toString());
      console.log('[DEBUG] selectedApp:', selectedApp);
      if (selectedApp) {
        console.log('[DEBUG] selectedApp.fromEmailAddress:', selectedApp.fromEmailAddress);
        console.log('[DEBUG] selectedApp.isInternalApp:', selectedApp.isInternalApp);
        
        // Check if this is an internal app using the isInternalApp flag
        const isInternalApp = selectedApp.isInternalApp;
        
        if (isInternalApp) {
          // For TP Internal apps, from email is configured during registration
          this.emailData.smtpUserEmail = selectedApp.fromEmailAddress || 'tp-internal@managed.local';
          this.emailData.appPassword = '';
          this.toastr.info(EMAIL_MESSAGES.TP_SERVICES_DETECTED, MESSAGE_TITLES.INFO);
        } else {
          // For external apps, use the fromEmailAddress
          this.emailData.smtpUserEmail = selectedApp.fromEmailAddress || '';
          this.emailData.appPassword = '';
        }
        console.log('[DEBUG] emailData.smtpUserEmail set to:', this.emailData.smtpUserEmail);
      }
    } else {
      this.emailData.smtpUserEmail = '';
      this.emailData.appPassword = '';
    }
    // FIX: Trigger change detection for OnPush strategy after updating emailData
    this.cdr.markForCheck();
  }

  async sendTestEmail() {
    // Check if using TP Internal config (toggle) or if selected app is internal
    const isUsingTPInternal = this.useTPInternalConfig;
    const selectedApp = !isUsingTPInternal && this.emailData.appId 
      ? this.applicationList.find(app => app.id.toString() === this.emailData.appId?.toString())
      : null;
    const isInternalApp = isUsingTPInternal || selectedApp?.isInternalApp || false;
    
    // Validate required fields
    // For TP Internal config: only need subject and toRecipients
    // For regular apps: need appId, smtpUserEmail, subject, toRecipients
    if (!this.emailData.subject || !this.emailData.toRecipients) {
      this.toastr.warning(EMAIL_MESSAGES.REQUIRED_FIELDS, MESSAGE_TITLES.WARNING);
      return;
    }
    
    // appId and smtpUserEmail required when NOT using TP Internal config
    if (!isUsingTPInternal && (!this.emailData.appId || !this.emailData.smtpUserEmail)) {
      this.toastr.warning(EMAIL_MESSAGES.REQUIRED_FIELDS, MESSAGE_TITLES.WARNING);
      return;
    }
    
    // AppPassword required for non-internal apps
    if (!isInternalApp && !this.emailData.appPassword) {
      this.toastr.warning(EMAIL_MESSAGES.APP_PASSWORD_REQUIRED, MESSAGE_TITLES.WARNING);
      return;
    }

    this.isSending = true;
    
    // For TP Internal config, use appId=0 for API call
    const apiAppId = isUsingTPInternal ? 0 : this.emailData.appId;
    const emailDataForApi = { ...this.emailData, appId: apiAppId };
    
    // Store AppPassword for guidance email in sessionStorage (skip for TP Internal)
    if (this.emailData.appId && !isUsingTPInternal) {
      await this.secureStorage.setItem(`app_${this.emailData.appId}_appPassword`, this.emailData.appPassword || '', true);
    }
    
    this.emailService.sendEmail(emailDataForApi, this.selectedFiles).pipe(
      switchMap((response: any) => {
        this.toastr.success(EMAIL_MESSAGES.TEST_EMAIL_SUCCESS, MESSAGE_TITLES.SUCCESS);
        
        // Skip guidance email for TP Internal config
        if (this.emailData.appId && !isUsingTPInternal) {
          const appId = +this.emailData.appId;
          // Explicitly fetch all necessary application details as per architectural direction
          return this.applicationService.getApplicationById(appId).pipe(
            switchMap(async (appDetails: any) => {
              const appInfo = appDetails?.data || appDetails;
              try {
                const ownerEmail = await this.secureStorage.getItem<string>(`app_${appId}_ownerEmail`, true);
                const appPassword = await this.secureStorage.getItem<string>(`app_${appId}_appPassword`, true);
                const appSecret = await this.secureStorage.getItem<string>(`app_${appId}_appSecret`, true);
                const coOwnerEmail = await this.secureStorage.getItem<string>(`app_${appId}_coOwnerEmail`, true);
                
                if (!ownerEmail || !appSecret || appPassword === null) {
                  this.toastr.warning(EMAIL_MESSAGES.GUIDANCE_MISSING_CREDENTIALS, MESSAGE_TITLES.WARNING);
                  return of(response);
                }
                
                this.secureStorage.removeItem(`app_${appId}_ownerEmail`, true);
                this.secureStorage.removeItem(`app_${appId}_appPassword`, true);
                this.secureStorage.removeItem(`app_${appId}_appSecret`, true);
                this.secureStorage.removeItem(`app_${appId}_coOwnerEmail`, true);
                
                const baseApiUrl = environment.apiUrl.replace(/\/api\/?$/, '');
                await this.applicationService.sendGuidanceEmail(appId, ownerEmail, appPassword, appSecret, baseApiUrl, coOwnerEmail || undefined).toPromise();
                this.toastr.info(EMAIL_MESSAGES.GUIDANCE_SUCCESS, MESSAGE_TITLES.INFO);
                return of(response);
              } catch (error: any) {
                const guidanceError = error?.error?.message || EMAIL_MESSAGES.GUIDANCE_FAILED;
                this.toastr.error(guidanceError, MESSAGE_TITLES.ERROR);
                return of(response);
              }
            }),
            catchError((error: any) => {
              return of(response);
            })
          );
        }
        return of(response);
      }),
      catchError((error: any) => {
        const errorMsg = error.error?.detail || EMAIL_MESSAGES.SEND_EMAIL_ERROR;
        this.toastr.error(errorMsg, MESSAGE_TITLES.ERROR);
        this.isSending = false;
        return of(null);
      })
    ).subscribe({
      next: (response: any) => {
        this.isSending = false;
        this.showTestForm = false;
        this.showTPAssistPreview = false;
        this.tpAssistPreview = '';
        this.loadEmails();
        // Reset form
        this.emailData = {
          subject: '',
          body: '',
          isHtml: false,
          toRecipients: '',
          ccRecipients: '',
          appId: '',
          appPassword: '',
          smtpUserEmail: '',
          useTPAssist: false
        };
        this.selectedFiles = [];
      },
      error: (err: any) => {
        const errorMsg = err.error?.detail || EMAIL_MESSAGES.SEND_EMAIL_ERROR;
        this.toastr.error(errorMsg, MESSAGE_TITLES.ERROR);
        this.isSending = false;
      }
    });
  }

  /**
   * Preview TPAssist enhancement - calls GetTPAssist API and displays result
   */
  async previewTPAssist(): Promise<void> {
    if (!this.emailData.body) {
      this.toastr.warning('Email body is required for TPAssist preview', MESSAGE_TITLES.WARNING);
      return;
    }

    this.isEnhancing = true;
    this.showTPAssistPreview = false;
    this.tpAssistPreview = '';
    this.cdr.markForCheck();

    try {
      const response: any = await firstValueFrom(
        this.emailService.getTPAssist({
          body: this.emailData.body,
          subject: this.emailData.subject,
          isHtml: this.emailData.isHtml
        })
      );

      if (response?.resultCode === 1 && response?.resultData?.[0]?.success) {
        this.tpAssistPreview = response.resultData[0].body;
        this.showTPAssistPreview = true;
        this.toastr.success('TPAssist enhancement preview ready', MESSAGE_TITLES.SUCCESS);
      } else {
        const errorMsg = response?.resultData?.[0]?.errorMessage || response?.resultMessages?.[0] || 'TPAssist enhancement failed';
        this.toastr.error(errorMsg, MESSAGE_TITLES.ERROR);
      }
    } catch (error: any) {
      const errorMsg = error?.error?.detail || 'Failed to get TPAssist preview';
      this.toastr.error(errorMsg, MESSAGE_TITLES.ERROR);
    } finally {
      this.isEnhancing = false;
      this.cdr.markForCheck();
    }
  }

  /**
   * Apply TPAssist preview to email body
   */
  applyTPAssistPreview(): void {
    if (this.tpAssistPreview) {
      this.emailData.body = this.tpAssistPreview;
      this.showTPAssistPreview = false;
      this.toastr.info('TPAssist enhancement applied to email body', MESSAGE_TITLES.INFO);
      this.cdr.markForCheck();
    }
  }

  // Compare function for ng-select to handle type coercion (number vs string)
  // When bindValue is used, ng-select passes the full item object as first param
  compareAppId = (item: any, selected: any): boolean => {
    if (item === null || selected === null || item === undefined || selected === undefined) {
      return false;
    }
    // item is the full object when bindValue is used, so we need to extract the id
    const itemId = typeof item === 'object' ? item?.id : item;
    return itemId?.toString() === selected?.toString();
  };

  isInternalApp(): boolean {
    // If using TP Internal config toggle, it's internal
    if (this.useTPInternalConfig) {
      return true;
    }
    if (!this.emailData.appId) {
      return false;
    }
    const selectedApp = this.applicationList.find((app: any) => app.id.toString() === this.emailData.appId?.toString());
    return selectedApp?.isInternalApp || false;
  }

  // Custom form validation that handles internal apps (no password required)
  isFormValid(): boolean {
    const result = {
      appId: this.emailData.appId,
      smtpUserEmail: this.emailData.smtpUserEmail,
      toRecipients: this.emailData.toRecipients,
      subject: this.emailData.subject,
      appPassword: this.emailData.appPassword,
      isInternal: this.isInternalApp()
    };
    console.log('[DEBUG] isFormValid check:', result);
    
    // Check required fields: appId, smtpUserEmail, toRecipients, subject
    if (!this.emailData.appId || !this.emailData.smtpUserEmail || !this.emailData.toRecipients || !this.emailData.subject) {
      console.log('[DEBUG] isFormValid: false (missing required fields)');
      return false;
    }
    
    // For external apps, appPassword is required
    if (!this.isInternalApp() && !this.emailData.appPassword) {
      console.log('[DEBUG] isFormValid: false (external app needs password)');
      return false;
    }
    
    console.log('[DEBUG] isFormValid: true');
    return true;
  }

  // Export emails to CSV
  exportToCSV() {
    if (!this.emailList || this.emailList.length === 0) {
      this.toastr.warning(EMAIL_MESSAGES.EXPORT_EMPTY, MESSAGE_TITLES.WARNING);
      return;
    }

    // Prepare CSV headers
    const headers = EMAIL_MESSAGES.CSV_HEADERS;
    
    // Prepare CSV rows
    const rows = this.emailList.map(email => [
      email.upn || '',
      email.username || '',
      email.appName || '',
      email.sender || '',
      this.escapeCSV(email.subject || ''),
      this.escapeCSV(email.body || ''),
      email.serviceName || '',
      new Date(email.creationDateTime).toLocaleDateString() || '',
      new Date(email.creationDateTime).toLocaleTimeString() || '',
      email.active === 1 ? EMAIL_MESSAGES.CSV_STATUS_DELIVERED : EMAIL_MESSAGES.CSV_STATUS_FAILED
    ]);

    // Create CSV content
    const csvContent = [
      headers.map(h => this.escapeCSV(h)).join(','),
      ...rows.map(row => row.map(cell => this.escapeCSV(String(cell))).join(','))
    ].join('\n');

    // Create blob and download
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', `Email_Logs_${new Date().getTime()}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    this.toastr.success(EMAIL_MESSAGES.EXPORT_SUCCESS, MESSAGE_TITLES.SUCCESS);
  }

  // Helper method to escape CSV values
  private escapeCSV(value: string): string {
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
  }

  // TrackBy functions for better performance with *ngFor
  trackByEmailId(index: number, email: any): string {
    return email.emailId || index;
  }

  trackByAppId(index: number, app: any): number {
    return app.id || index;
  }

  setViewMode(mode: 'list' | 'card') {
    this.viewMode = mode;
    this.cdr.markForCheck();
  }

  async clearFilters(): Promise<void> {
    this.searchTerm = '';
    this.selectedAppName = '';
    this.currentPage = 1;
    await this.loadEmails();
  }

  // Email Detail Modal Methods
  openEmailDetail(emailId: string): void {
    this.selectedEmailId = emailId;
    this.showEmailDetailModal = true;
    this.cdr.markForCheck();
  }

  closeEmailDetailModal(): void {
    this.showEmailDetailModal = false;
    this.selectedEmailId = null;
    this.cdr.markForCheck();
  }
}
