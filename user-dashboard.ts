import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { NgSelectModule } from '@ng-select/ng-select';
import { RouterModule } from '@angular/router';
import { DomSanitizer, SafeUrl } from '@angular/platform-browser';
import { DashboardService } from '../../services/dashboard';
import { AuthService } from '../../services/auth';
import { ApplicationService } from '../../services/application';
import { forkJoin, firstValueFrom } from 'rxjs';
import { DASHBOARD_LABELS } from '../../shared/constants/messages';
import { IMAGE_PATHS } from '../../shared/constants/image-paths';

declare var Chart: any;

@Component({
  selector: 'app-user-dashboard',
  standalone: true,
  imports: [CommonModule, FormsModule, NgSelectModule, RouterModule],
  templateUrl: './user-dashboard.html',
  styleUrl: './user-dashboard.scss'
})
export class UserDashboardComponent implements OnInit {
  private dashboardService = inject(DashboardService);
  private authService = inject(AuthService);
  private applicationService = inject(ApplicationService);
  private sanitizer = inject(DomSanitizer);

  public readonly IMAGE_PATHS = IMAGE_PATHS;
  userProfileImage: SafeUrl | string = IMAGE_PATHS.USER_PROFILE;

  private chart: any;
  private pieChart: any;

  userProfile: any = null;
  unverifiedApplications: any[] = [];
  appList: any[] = [];
  totalSentEmail = 0;
  monthlyEmail = 0;
  todayAllEmail = 0;
  lastSevenDaysEmail = 0;
  lastThirtyDaysEmail = 0;
  yearlyEmail = 0;
  totalApplications = 0;
  emailCount: any[] = [];
  top10Apps: any[] = [];
  selectedAppId: number = 0;

  get selectedAppName(): string {
    const selected = this.emailCount.find(x => x.appId === this.selectedAppId);
    return selected?.appName || 'All';
  }

  getTop10Apps(): any[] {
    return this.top10Apps;
  }

  async ngOnInit(): Promise<void> {
    const token = this.authService.getTokenFromCache();
    if (!token) return;
    const payload = JSON.parse(atob(token.split('.')[1]));
    const userId = payload['nameid'] || payload['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'];

    try {
      const results: any = await firstValueFrom(forkJoin({
        profile: this.dashboardService.getUserProfile(userId),
        dashboard: this.dashboardService.getAdminDashboardData(),
        top10: this.dashboardService.getTop10Apps(),
        userInfo: this.authService.getUserInfo(),
        applications: this.applicationService.getApplications(1, 100)
      }));

      // Get application list
      this.appList = results.applications?.data || [];

      // Handle profile - may be in data array or directly
      const profileData = results.profile?.resultData?.[0] || results.profile;
      this.userProfile = profileData;
      
      // Get user info
      const userInfoData = results.userInfo?.resultData?.[0] || results.userInfo;
      if (this.userProfile && userInfoData?.email) {
        this.userProfile.email = userInfoData.email;
      }

      // Fetch profile photo if UPN is available
      if (this.userProfile && this.userProfile.upn) {
        try {
          const photoResponse = await firstValueFrom(
            this.applicationService.getADUserPhoto(this.userProfile.upn)
          );
          if (photoResponse?.success && photoResponse?.data) {
            this.userProfileImage = this.sanitizer.bypassSecurityTrustUrl(photoResponse.data);
            this.userProfile.profileImageBase64 = photoResponse.data;
          }
        } catch (photoError) {
          console.warn('Could not fetch profile photo:', photoError);
          this.userProfileImage = this.IMAGE_PATHS.USER_PROFILE;
        }
      } else {
        this.userProfileImage = this.IMAGE_PATHS.USER_PROFILE;
      }

      // Set default values if profile is missing some fields
      if (this.userProfile) {
        this.userProfile.applications = this.userProfile.applications || [];
        this.userProfile.appName = this.userProfile.appName || 'No applications yet';
        this.userProfile.creationDateTime = this.userProfile.createdDateTime || this.userProfile.creationDateTime || new Date();
      }

      if (this.userProfile && this.userProfile.applications) {
        this.unverifiedApplications = this.userProfile.applications.filter((app: any) => app.active === 1 && !app.isVerified);
      }

      const allDashboardData = results.dashboard?.resultData || [];
      this.top10Apps = (results.top10?.resultData || []).filter((x: any) => x.totalSentEmail > 0);
      this.emailCount = [...allDashboardData.filter((x: any) => x.appId !== 0)];
      // Use appList.length for actual application count (not email count data)
      this.totalApplications = this.appList.length;

      // Add "ALL" option - always present
      this.emailCount.push({
        appId: 0,
        appName: DASHBOARD_LABELS.ALL_APPLICATIONS,
        todayEmail: this.emailCount.reduce((sum, count) => sum + (count.todayEmail || 0), 0),
        lastSevenDaysEmail: this.emailCount.reduce((sum, count) => sum + (count.lastSevenDaysEmail || 0), 0),
        lastThirtyDaysEmail: this.emailCount.reduce((sum, count) => sum + (count.lastThirtyDaysEmail || 0), 0),
        monthlyEmail: this.emailCount.reduce((sum, count) => sum + (count.monthlyEmail || 0), 0),
        yearlyEmail: this.emailCount.reduce((sum, count) => sum + (count.yearlyEmail || 0), 0),
        totalSentEmail: this.emailCount.reduce((sum, count) => sum + (count.totalSentEmail || 0), 0),
      });
      
      this.onchangeApp(0);
      // Use setTimeout to allow Angular to render the content before accessing the canvas
      setTimeout(() => this.initChart(), 150);
    } catch (err) {
      console.error('Error loading dashboard data:', err);
      // Set minimal profile so UI renders
      this.userProfile = {
        email: 'User',
        appName: 'No applications',
        applications: [],
        creationDateTime: new Date()
      };
      this.userProfileImage = this.IMAGE_PATHS.USER_PROFILE;
      this.emailCount = [{
        appId: 0,
        appName: DASHBOARD_LABELS.ALL_APPLICATIONS,
        todayEmail: 0,
        lastSevenDaysEmail: 0,
        lastThirtyDaysEmail: 0,
        monthlyEmail: 0,
        yearlyEmail: 0,
        totalSentEmail: 0,
      }];
      this.onchangeApp(0);
      setTimeout(() => this.initChart(), 150);
    }
  }

  onchangeApp(appId: any) {
    if (appId && typeof appId === 'object') {
      this.selectedAppId = +appId.appId;
    } else {
      this.selectedAppId = +appId;
    }
    const appData = this.emailCount.find(x => x.appId === this.selectedAppId);
    if (appData) {
      this.totalSentEmail = appData.totalSentEmail;
      this.todayAllEmail = appData.todayEmail;
      this.monthlyEmail = appData.monthlyEmail;
      this.lastSevenDaysEmail = appData.lastSevenDaysEmail;
      this.lastThirtyDaysEmail = appData.lastThirtyDaysEmail;
      this.yearlyEmail = appData.yearlyEmail;
    }
    // Rebuild breakdown chart to reflect new selection
    setTimeout(() => this.initChart(), 0);
  }

  initChart() {
    const canvas = document.getElementById('myChart') as HTMLCanvasElement;
    if (!canvas) {
      console.log('Bar chart canvas not found');
      return;
    }

    const barCharData = this.emailCount.filter(x => x.appId !== 0).sort((a, b) => a.appName.localeCompare(b.appName));
    const labels = barCharData.map(x => x.appName);
    const emails = barCharData.map(x => x.totalSentEmail);
    console.log('Chart data - emailCount:', this.emailCount);
    console.log('Chart data - barCharData:', barCharData);
    console.log('Chart labels:', labels);
    console.log('Chart emails:', emails);

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Build gradient palette
    const gradients = labels.map((_, i) => {
      const g = ctx.createLinearGradient(0, 0, canvas.width, 0);
      const hue = (i * 37) % 360;
      g.addColorStop(0, `hsla(${hue}, 85%, 60%, 0.95)`);
      g.addColorStop(1, `hsla(${(hue + 25) % 360}, 85%, 45%, 0.95)`);
      return g;
    });

    if (this.chart) { this.chart.destroy(); }
    this.chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: DASHBOARD_LABELS.BAR_LABEL_SENT_EMAIL,
          data: emails,
          backgroundColor: gradients,
          borderRadius: 8,
          borderSkipped: false,
          barThickness: 18,
          maxBarThickness: 22
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        animation: {
          duration: 900,
          easing: 'easeOutQuart'
        },
        plugins: {
          tooltip: {
            enabled: true,
            callbacks: {
              label: (context: any) => ` Total: ${context.parsed.x.toLocaleString()}`
            }
          },
          legend: {
            display: false
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(0,0,0,0.05)' },
            ticks: { color: '#6c757d' }
          },
          y: {
            grid: { display: false },
            ticks: { color: '#343a40' }
          }
        }
      }
    });

    // Build breakdown doughnut for selected app
    const breakdownCanvas = document.getElementById('breakdownChartUser') as HTMLCanvasElement;
    if (breakdownCanvas) {
      const bctx = breakdownCanvas.getContext('2d');
      if (bctx) {
        const selected = this.emailCount.find(x => x.appId === this.selectedAppId) || {
          todayEmail: 0,
          lastSevenDaysEmail: 0,
          lastThirtyDaysEmail: 0,
          monthlyEmail: 0,
          yearlyEmail: 0
        };
        const labelsPie = ['Today', '7 Days', '30 Days', 'Monthly', 'Yearly'];
        const dataPie = [
          selected.todayEmail || 0,
          selected.lastSevenDaysEmail || 0,
          selected.lastThirtyDaysEmail || 0,
          selected.monthlyEmail || 0,
          selected.yearlyEmail || 0
        ];
        if (this.pieChart) { this.pieChart.destroy(); }
        this.pieChart = new Chart(bctx, {
          type: 'doughnut',
          data: {
            labels: labelsPie,
            datasets: [{
              data: dataPie,
              backgroundColor: [
                'rgba(54, 162, 235, 0.9)',
                'rgba(255, 206, 86, 0.9)',
                'rgba(75, 192, 192, 0.9)',
                'rgba(153, 102, 255, 0.9)',
                'rgba(255, 99, 132, 0.9)'
              ],
              borderColor: '#ffffff',
              borderWidth: 2
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '58%',
            plugins: {
              legend: { position: 'bottom' },
              tooltip: {
                callbacks: {
                  label: (context: any) => ` ${context.label}: ${context.parsed.toLocaleString()}`
                }
              }
            }
          }
        });
      }
    }
  }
}