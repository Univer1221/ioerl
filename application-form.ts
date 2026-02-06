import { Component, OnInit, inject, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { NgSelectModule } from '@ng-select/ng-select';
import { RouterModule, ActivatedRoute, Router } from '@angular/router';
import { ApplicationService } from '../../../services/application';
import { AuthService } from '../../../services/auth';
import { SecureStorageService } from '../../../services/secure-storage.service';
import { ToastrService } from 'ngx-toastr';
import { switchMap, tap, debounceTime, distinctUntilChanged, catchError } from 'rxjs/operators';
import { of, Subject, firstValueFrom } from 'rxjs';
import { APPLICATION_LABELS, APPLICATION_MESSAGE_FORMATTERS, APPLICATION_MESSAGES, MESSAGE_TITLES } from '../../../shared/constants/messages';

@Component({
  selector: 'app-application-form',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule, NgSelectModule],
  templateUrl: './application-form.html',
  styleUrl: './application-form.scss'
})
export class ApplicationFormComponent implements OnInit {
  private appService = inject(ApplicationService);
  private authService = inject(AuthService);
  private secureStorage = inject(SecureStorageService);
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private toastr = inject(ToastrService);
  private cdr = inject(ChangeDetectorRef);

  appData: any = {
    id: 0,
    appName: '',
    description: '',
    appOwner: '',
    ownerEmail: '',
    coOwner: '',
    coOwnerEmail: '',
    userId: '',
    fromEmailAddress: '',
    fromEmailDisplayName: '',
    emailServiceId: null,
    emailServer: '',
    port: null,
    active: 0,
    isInternalApp: false,
    createdBy: '',
    creationDateTime: new Date().toISOString(),
    modifiedBy: '',
    modificationDateTime: new Date().toISOString()
  };

  isEdit: boolean = false;
  users: any[] = [];
  emailServices: any[] = [];
  smtpProvider: string = 'External';
  smtpProviders: any[] = APPLICATION_LABELS.SMTP_PROVIDERS;
  availableFromEmailDomains: string[] = [];
  fromEmailLocalPart: string = 'support';
  fromEmailDomain: string = '';
  error: string = '';

  adUsers: any[] = [];
  ownerSearchInput$ = new Subject<string>();
  adUserLoading: boolean = false;
  selectedAdUser: any = null;

  coOwnerAdUsers: any[] = [];
  coOwnerSearchInput$ = new Subject<string>();
  coOwnerLoading: boolean = false;
  selectedCoOwner: any = null;

  async ngOnInit(): Promise<void> {
    const id = this.route.snapshot.paramMap.get('Id');
    if (id) {
      this.isEdit = true;
      await this.loadApplication(+id);
    } else {
      this.appData.createdBy = await this.authService.getUserId();
    }
    
    await Promise.all([this.loadUsers(), this.loadEmailServices()]);
    this.setupAdUserSearch();
  }

  setupAdUserSearch(): void {
    // Owner search typeahead with debounce
    this.ownerSearchInput$.pipe(
      tap(term => {
        if (term && term.length >= 3) {
          this.adUserLoading = true;
          this.cdr.markForCheck();
        }
      }),
      debounceTime(500),
      distinctUntilChanged(),
      switchMap(term => {
        if (!term || term.length < 3) {
          this.adUserLoading = false;
          this.adUsers = [];
          this.cdr.markForCheck();
          return of({ users: [] });
        }
        return this.appService.searchADUsers(term).pipe(
          catchError(() => of({ users: [] }))
        );
      })
    ).subscribe(response => {
      this.adUserLoading = false;
      if (response && response.users) {
        this.adUsers = response.users.filter((u: any) => u.mail).map((u: any) => ({ ...u, photoUrl: null }));
        this.adUsers.forEach((u: any) => this.loadUserPhoto(u, 'owner'));
      }
      this.cdr.markForCheck();
    });

    // Co-Owner search typeahead with debounce
    this.coOwnerSearchInput$.pipe(
      tap(term => {
        if (term && term.length >= 3) {
          this.coOwnerLoading = true;
          this.cdr.markForCheck();
        }
      }),
      debounceTime(500),
      distinctUntilChanged(),
      switchMap(term => {
        if (!term || term.length < 3) {
          this.coOwnerLoading = false;
          this.coOwnerAdUsers = [];
          this.cdr.markForCheck();
          return of({ users: [] });
        }
        return this.appService.searchADUsers(term).pipe(
          catchError(() => of({ users: [] }))
        );
      })
    ).subscribe(response => {
      this.coOwnerLoading = false;
      if (response && response.users) {
        this.coOwnerAdUsers = response.users.filter((u: any) => u.mail).map((u: any) => ({ ...u, photoUrl: null }));
        this.coOwnerAdUsers.forEach((u: any) => this.loadUserPhoto(u, 'coOwner'));
      }
      this.cdr.markForCheck();
    });
  }

  loadUserPhoto(user: any, type: 'owner' | 'coOwner'): void {
    this.appService.getADUserPhoto(user.mail).subscribe(res => {
      if (res?.success && res?.data) {
        user.photoUrl = res.data;
        if (type === 'owner') this.adUsers = [...this.adUsers];
        else this.coOwnerAdUsers = [...this.coOwnerAdUsers];
      }
    });
  }

  // Allow adding custom owner name (manual entry)
  addCustomOwner = (term: string) => {
    return { displayName: term, userPrincipalName: '', mail: '' };
  };

  onAdUserSelect(user: any): void {
    if (user) {
      this.appData.appOwner = user.displayName;
      if (user.mail) this.appData.ownerEmail = user.mail;
      this.selectedAdUser = user;
      // Regenerate from email if TPInternal is selected
      if (this.isTPInternal()) {
        this.generateFromEmailAddressForTPInternal();
      }
    }
  }

  onAdUserClear(): void {
    this.appData.appOwner = '';
    this.appData.ownerEmail = '';
    this.selectedAdUser = null;
    this.adUsers = [];
  }

  onCoOwnerSelect(user: any): void {
    if (user) {
      this.appData.coOwner = user.displayName;
      if (user.mail) this.appData.coOwnerEmail = user.mail;
      this.selectedCoOwner = user;
    }
  }

  onCoOwnerClear(): void {
    this.appData.coOwner = '';
    this.appData.coOwnerEmail = '';
    this.selectedCoOwner = null;
    this.coOwnerAdUsers = [];
  }

  async loadApplication(id: number): Promise<void> {
    try {
      const response = await firstValueFrom(this.appService.getApplicationById(id));
      if (response && response.resultData && response.resultData.length > 0) {
        this.appData = response.resultData[0];
        this.appData.modifiedBy = await this.authService.getUserId();
        // Set smtpProvider based on isInternalApp flag
        this.smtpProvider = this.appData.isInternalApp ? 'TPInternal' : 'External';
        if (this.appData.appOwner) {
          this.selectedAdUser = { displayName: this.appData.appOwner, mail: this.appData.ownerEmail || '' };
        }
        if (this.appData.coOwner) {
          this.selectedCoOwner = { displayName: this.appData.coOwner, mail: this.appData.coOwnerEmail || '' };
        }
      }
    } catch (err: any) {
      this.toastr.error(APPLICATION_MESSAGES.LOAD_ERROR, MESSAGE_TITLES.ERROR);
    }
  }

  async loadUsers(): Promise<void> {
    try {
      const response = await firstValueFrom(this.appService.getUsersDDL());
      if (response && response.resultData) {
        this.users = response.resultData;
        const role = await this.authService.getRole();
        if (role === 'USER') {
          const currentUserId = await this.authService.getUserId();
          this.users = this.users.filter(u => u.userId === currentUserId);
          if (!this.isEdit) {
            this.appData.userId = currentUserId;
          }
        }
      }
    } catch (error) {
      // Silently handle error
    }
  }

  async loadEmailServices(): Promise<void> {
    try {
      const response = await firstValueFrom(this.appService.getEmailServiceLookups());
      if (response && response.resultData) {
        this.emailServices = response.resultData;
      }
    } catch (error) {
      // Silently handle error
    }
  }

  async onSubmit(): Promise<void> {
    if (this.isEdit) {
      this.appService.updateApplication(this.appData).subscribe({
        next: (response: any) => {
          this.toastr.success(
            APPLICATION_MESSAGE_FORMATTERS.updateSuccess(this.appData.appName),
            MESSAGE_TITLES.SUCCESS
          );
          this.router.navigate(['/Admin/Application/List']);
        },
        error: (err: any) => {
          this.error = err.error?.detail || APPLICATION_MESSAGES.UPDATE_ERROR;
          this.toastr.error(this.error, MESSAGE_TITLES.ERROR);
        }
      });
    } else {
      const role = await this.authService.getRole();
      this.appData.active = (role === 'ADMIN') ? 1 : 0;

      this.appService.addApplication(this.appData).subscribe({
        next: async (response: any) => {
          if (response?.resultData?.[0]?.id && response?.resultData?.[0]?.appSecret) {
            const appId = response.resultData[0].id;
            const appSecret = response.resultData[0].appSecret;
            this.toastr.success(
              APPLICATION_MESSAGE_FORMATTERS.saveSuccess(this.appData.appName),
              MESSAGE_TITLES.SUCCESS
            );
            
            const storePromises: Promise<void>[] = [];
            if (this.appData.ownerEmail) storePromises.push(this.secureStorage.setItem(`app_${appId}_ownerEmail`, this.appData.ownerEmail, true));
            if (this.appData.coOwnerEmail) storePromises.push(this.secureStorage.setItem(`app_${appId}_coOwnerEmail`, this.appData.coOwnerEmail, true));
            storePromises.push(this.secureStorage.setItem(`app_${appId}_appSecret`, appSecret, true));
            await Promise.all(storePromises);
            
            const currentRole = await this.authService.getRole();
            // Navigate to send test email page with appId
            // The guidance email will be sent AFTER user sends test email, not automatically
            if (currentRole === 'ADMIN') {
              // Redirect admin to test mail page with the application ID pre-selected
              this.router.navigate(['/Admin/Email/List'], { queryParams: { appId: appId } });
            } else {
              this.router.navigate(['/Admin/Application/List']);
            }
          }
        },
        error: (err: any) => {
          this.error = err.error?.detail || APPLICATION_MESSAGES.SAVE_ERROR;
          this.toastr.error(this.error, MESSAGE_TITLES.ERROR);
        }
      });
    }
  }

  shouldShowServer(): boolean {
    if (!this.appData.emailServiceId) return false;
    const selectedService = this.emailServices.find(s => s.id === this.appData.emailServiceId);
    if (!selectedService) return false;
    const serviceType = selectedService.type.toString();
    // Show server for SMTP (1), SMTPS (2), SendGrid (4)
    return serviceType === '1' || serviceType === '0' || serviceType === '4';
  }

  shouldShowPort(): boolean {
    if (!this.appData.emailServiceId) return false;
    const selectedService = this.emailServices.find(s => s.id === this.appData.emailServiceId);
    if (!selectedService) return false;
    const serviceType = selectedService.type.toString();
    // Show port for SMTP (1), SMTPS (0/2)
    return serviceType === '1' || serviceType === '0';
  }

  isTPInternal(): boolean {
    return this.smtpProvider === 'TPInternal';
  }

  onSmtpProviderChange(): void {
    if (this.isTPInternal()) {
      // Set isInternalApp flag to true for TPInternal
      this.appData.isInternalApp = true;
      // Populate from email based on owner's domain
      this.generateFromEmailAddressForTPInternal();
      this.appData.emailServer = '';
      this.appData.port = null;
      // Set emailServiceId to 0 for TP Internal (ID 0 = TP Internal in static lookup)
      this.appData.emailServiceId = 0;
    } else {
      // Set isInternalApp flag to false for External
      this.appData.isInternalApp = false;
    }
  }

  private generateFromEmailAddressForTPInternal(): void {
    const currentEmail = this.appData.fromEmailAddress || '';
    if (currentEmail.includes('@')) {
      const [local, domain] = currentEmail.split('@');
      this.fromEmailLocalPart = local || this.fromEmailLocalPart || 'support';
      this.fromEmailDomain = domain || this.fromEmailDomain || '';
    }

    // Extract domain from owner email (e.g., abcd@zdomain.com → zdomain.com)
    const ownerDomain = this.appData.ownerEmail?.split('@')[1]?.toLowerCase() || '';
    const defaultDomains = ['teleperformance.com', 'teleperformanceusa.com'];
    const domainSuggestions = ownerDomain ? [ownerDomain, ...defaultDomains] : defaultDomains;
    this.availableFromEmailDomains = [...new Set(domainSuggestions)];

    if (!this.fromEmailDomain) {
      this.fromEmailDomain = ownerDomain || defaultDomains[0] || '';
    }

    this.updateFromEmailAddress();
  }

  onFromEmailDomainChange(): void {
    this.updateFromEmailAddress();
  }

  onFromEmailLocalPartChange(): void {
    this.updateFromEmailAddress();
  }

  private updateFromEmailAddress(): void {
    const local = (this.fromEmailLocalPart || '').trim();
    const domain = (this.fromEmailDomain || '').trim();
    if (local && domain) {
      this.appData.fromEmailAddress = `${local}@${domain}`;
    } else if (domain) {
      this.appData.fromEmailAddress = domain.includes('@') ? domain : `support@${domain}`;
    } else {
      this.appData.fromEmailAddress = '';
    }
  }
}
