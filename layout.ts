import { Component, inject, OnInit, HostListener, ElementRef, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { DomSanitizer, SafeUrl } from '@angular/platform-browser';
import { firstValueFrom } from 'rxjs';
import { AuthService } from '../../services/auth';
import { ApplicationService } from '../../services/application';
import { ToastrService } from 'ngx-toastr';
import { IMAGE_PATHS } from '../../shared/constants/image-paths';
import { MESSAGE_TITLES, SESSION_MESSAGES } from '../../shared/constants/messages';

@Component({
  selector: 'app-layout',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './layout.html',
  styleUrl: './layout.scss',
  encapsulation: ViewEncapsulation.None
})
export class LayoutComponent implements OnInit {
  public readonly IMAGE_PATHS = IMAGE_PATHS;
  private authService = inject(AuthService);
  private applicationService = inject(ApplicationService);
  private router = inject(Router);
  private toastr = inject(ToastrService);
  private elementRef = inject(ElementRef);
  private sanitizer = inject(DomSanitizer);

  role: string | null = '';
  email: string | null = '';
  displayName: string | null = '';
  dashboardUrl = '';
  isSidebarCollapsed = false;
  isUserDropdownOpen = false;
  headerProfileImage: SafeUrl | string = IMAGE_PATHS.USER_PROFILE;

  @HostListener('document:click', ['$event'])
  onDocumentClick(event: MouseEvent) {
    if (!this.elementRef.nativeElement.contains(event.target)) {
      this.isUserDropdownOpen = false;
    }
  }

  toggleUserDropdown(event: Event) {
    event.stopPropagation();
    this.isUserDropdownOpen = !this.isUserDropdownOpen;
  }

  async ngOnInit(): Promise<void> {
    this.role = await this.authService.getRole();
    this.email = await this.authService.getEmail();
    this.dashboardUrl = '/Dashboard'; // Common dashboard for all roles

    // Fetch decrypted user info to update the email and name display
    try {
      const response = await firstValueFrom(this.authService.getUserInfo());
      if (response && response.resultCode === 1 && response.resultData && response.resultData.length > 0) {
        const userInfo = response.resultData[0];
        this.email = userInfo.email;
        // Use username from backend, fallback to extracting from email
        this.displayName = userInfo.username || (this.email ? this.email.split('@')[0].replace(/[._]/g, ' ') : 'User');
        await this.authService.updateLoginEmail(this.email!);

        // Fetch profile photo if UPN is available
        if (userInfo.upn) {
          try {
            const photoResponse = await firstValueFrom(
              this.applicationService.getADUserPhoto(userInfo.upn)
            );
            if (photoResponse?.success && photoResponse?.data) {
              this.headerProfileImage = this.sanitizer.bypassSecurityTrustUrl(photoResponse.data);
            }
          } catch (photoError) {
            console.warn('Could not fetch profile photo:', photoError);
            this.headerProfileImage = this.IMAGE_PATHS.USER_PROFILE;
          }
        } else {
          this.headerProfileImage = this.IMAGE_PATHS.USER_PROFILE;
        }
      }
    } catch (error) {
      console.error('Error fetching user info:', error);
      this.headerProfileImage = this.IMAGE_PATHS.USER_PROFILE;
    }
  }

  async logout(): Promise<void> {
    // Show toast first, then logout (logout will redirect to Azure logout page)
    this.toastr.info(SESSION_MESSAGES.LOGOUT_SUCCESS, MESSAGE_TITLES.SESSION_ENDED);
    await this.authService.logout();
  }

  toggleSidebar() {
    this.isSidebarCollapsed = !this.isSidebarCollapsed;
    // No body class manipulation needed - layout uses host class binding
  }
}
