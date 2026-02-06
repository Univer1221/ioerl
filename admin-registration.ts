import { Component, OnInit, inject, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { NgSelectModule } from '@ng-select/ng-select';
import { firstValueFrom, Subject, of } from 'rxjs';
import { debounceTime, distinctUntilChanged, switchMap, catchError, tap } from 'rxjs/operators';
import { UserService } from '../../services/user';
import { ApplicationService } from '../../services/application';
import { Router } from '@angular/router';
import { ADMIN_REGISTRATION_MESSAGES, MESSAGE_TITLES } from '../../shared/constants/messages';

declare var Swal: any;

@Component({
  selector: 'app-admin-registration',
  standalone: true,
  imports: [CommonModule, FormsModule, NgSelectModule],
  templateUrl: './admin-registration.html',
  styleUrl: './admin-registration.scss'
})
export class AdminRegistrationComponent implements OnInit {
  private userService = inject(UserService);
  private appService = inject(ApplicationService);
  private router = inject(Router);
  private cdr = inject(ChangeDetectorRef);

  registrationData: any = {
    email: '',
    username: '',
    upn: '',
    roleId: ''
  };

  roles: any[] = [];
  message: string = '';
  isLoading: boolean = false;

  adUsers: any[] = [];
  adUserSearchInput$ = new Subject<string>();
  adUserLoading: boolean = false;
  selectedAdUser: any = null;

  async ngOnInit(): Promise<void> {
    await this.loadRoles();
    this.setupAdUserSearch();
  }

  async loadRoles(): Promise<void> {
    try {
      const response = await firstValueFrom(this.userService.getRoles());
      if (response && response.resultData && response.resultData.length > 0) {
        this.roles = response.resultData;
      }
    } catch (error) {
      console.error('Error loading roles:', error);
    }
  }

  setupAdUserSearch(): void {
    // AD User search typeahead with debounce
    this.adUserSearchInput$.pipe(
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
        this.adUsers.forEach((u: any) => this.loadUserPhoto(u));
      }
      this.cdr.markForCheck();
    });
  }

  loadUserPhoto(user: any): void {
    this.appService.getADUserPhoto(user.mail).subscribe(res => {
      if (res?.success && res?.data) {
        user.photoUrl = res.data;
        this.adUsers = [...this.adUsers];
      }
    });
  }

  addCustomUser = (term: string) => ({ displayName: term, mail: '', userPrincipalName: '' });

  onAdUserSelect(user: any): void {
    if (user) {
      this.registrationData.username = user.displayName || '';
      this.registrationData.email = user.mail || '';
      this.registrationData.upn = user.userPrincipalName || user.mail || '';
      this.selectedAdUser = user;
    }
  }

  onAdUserClear(): void {
    this.registrationData.username = '';
    this.registrationData.email = '';
    this.registrationData.upn = '';
    this.selectedAdUser = null;
    this.adUsers = [];
  }

  goBack() {
    this.router.navigate(['/User/UserDetails']);
  }

  async onSubmit(): Promise<void> {
    this.isLoading = true;
    this.message = '';
    
    const payload = {
      ...this.registrationData,
      active: 1
    };

    try {
      await firstValueFrom(this.userService.registerUserByAdmin(payload));
      await Swal.fire({
        icon: 'success',
        title: MESSAGE_TITLES.SUCCESS,
        text: ADMIN_REGISTRATION_MESSAGES.REGISTRATION_SUCCESS(this.registrationData.email),
        showConfirmButton: false,
        timer: 2500
      });
      this.router.navigate(['/User/UserDetails']);
    } catch (err: any) {
      this.message = err.error?.detail || err.error?.resultMessages?.[0] || ADMIN_REGISTRATION_MESSAGES.REGISTRATION_ERROR;
    } finally {
      this.isLoading = false;
    }
  }
}
