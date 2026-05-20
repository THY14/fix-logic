# Forget Password — Integration Task

## Flow Overview

```
[Reset Password Page]
  User types phone or email → clicks "បញ្ជូន"
    → POST /auth/forget-password { username }
    → API saves OTP (123456 in dev) to DB
    → OTP dialog opens

[OTP Dialog]
  User types 123456 → clicks "ផ្ទៀងផ្ទាត់"
    → dialog closes with { verified: true, otp: "123456" }
    → Password dialog opens

[Password Dialog]
  User types new password → clicks submit
    → POST /auth/reset-password { username, otp, new_password, confirm_password }
    → API verifies OTP, updates password, deletes OTP
    → navigate to /auth
```

---

## Changed Files

---

### FILE 1 — `api/src/app/resources/r1-account/auth/forget-password/forget-password.service.ts`

**What changed:** `getUserByUsername()` — was exact match, now case-insensitive email lookup using `LOWER()`.

```ts
// ===========================================================================>> Core Library
import { BadRequestException, Injectable } from '@nestjs/common';
import { randomInt }                       from 'crypto';
import { DataSource }                      from 'typeorm';

// ===========================================================================>> Custom Library
import { appConfig }                       from 'src/app.config';
import { UserOTP }                         from 'src/model/user/otp.entity';
import { User }                            from 'src/model/user/users.entity';
import { ForgetPasswordDto, ResetPasswordDto } from './forget-password.dto';

@Injectable()
export class ForgetPasswordService {
    constructor(private readonly _dataSource: DataSource) { }

    private generateOtp(): string {
        if (appConfig.APP.ENV === 'development' && appConfig.AUTH.OTP_FIXED_CODE) {
            return appConfig.AUTH.OTP_FIXED_CODE;
        }
        return randomInt(0, 1_000_000).toString().padStart(6, '0');
    }

    // CHANGED: was findOne({ where: [{ phone }, { email }] }) — exact case match only
    // NOW: createQueryBuilder with LOWER() so email is case-insensitive
    private async getUserByUsername(username: string) {
        const user = await this._dataSource.getRepository(User)
            .createQueryBuilder('user')
            .where('user.phone = :username', { username })
            .orWhere('LOWER(user.email) = LOWER(:username)', { username })
            .getOne();

        if (!user || user.deleted_at) throw new BadRequestException('User not found');

        return user;
    }

    async forgetPassword(dto: ForgetPasswordDto) {
        const user = await this.getUserByUsername(dto.username);
        const otp = this.generateOtp();
        const otpRepo = this._dataSource.getRepository(UserOTP);

        await otpRepo.delete({ user_id: user.id });
        await otpRepo.save({
            user_id   : user.id,
            otp,
            expires_at: new Date(Date.now() + 5 * 60 * 1000),
        });

        return {
            status_code         : 200,
            go_to_reset_password: true,
            contact             : dto.username,
            message             : 'OTP sent successfully',
        };
    }

    async resetPassword(dto: ResetPasswordDto) {
        if (dto.new_password !== dto.confirm_password) throw new BadRequestException('Passwords do not match');

        const user = await this.getUserByUsername(dto.username);
        const otpRepo = this._dataSource.getRepository(UserOTP);

        const otpData = await otpRepo.findOne({
            where: { user_id: user.id, otp: dto.otp },
            order: { id: 'DESC' },
        });

        if (!otpData) throw new BadRequestException('Invalid OTP');
        if (otpData.expires_at < new Date()) throw new BadRequestException('OTP expired');

        await user.setPassword(dto.new_password);

        await this._dataSource.transaction(async (manager) => {
            await manager.getRepository(User).save({ id: user.id, password: user.password });
            await manager.getRepository(UserOTP).delete({ user_id: user.id });
        });

        return {
            status_code: 200,
            message    : 'Password reset successfully',
        };
    }
}
```

---

### FILE 2 — `api/src/app/resources/r1-account/auth/login/login.service.ts`

**What changed:**
- `login()` — was `findOne({ where: { phone } })`, now supports phone OR email
- `verifyOtp()` — was `user.phone = :phone`, now phone OR email
- `resendOtp()` — was `findOne({ where: { phone } })`, now supports phone OR email

```ts
import { BadRequestException, Injectable, UnauthorizedException } from "@nestjs/common";
import * as bcrypt from 'bcrypt';
import { randomInt } from 'crypto';
import * as jwt from 'jsonwebtoken';
import { LoginRequestDto, VerifyOtptDto } from "./login.dto";
import jwtConstants from "shared/jwt/constants";
import { DataSource } from "typeorm";
import { User } from "src/model/user/users.entity";
import { UserPayload } from "src/interface/jwt.interface";
import { UserOTP } from "src/model/user/otp.entity";
import { appConfig } from "src/app.config";
import { UserSessions } from "src/model/user/user_sessions.entity";
import { UserSessionLogs } from "src/model/user/user_session_logs.entity";

interface ClientInfo {
    ip: string | null;
    browser: string;
    platform: string;
    os: string;
    device_name: string;
    device_type: string;
    user_agent: string;
    location?: {
        country_code?: string | null;
        region?: string | null;
        city?: string | null;
        latitude?: number | null;
        longitude?: number | null;
        timezone?: string | null;
    };
}

interface RefreshPayload {
    user: UserPayload;
    type: 'refresh';
    iat?: number;
    exp?: number;
}

@Injectable()
export class LoginService {
    constructor(private dataSourse: DataSource) { }

    private generateOtp(): string {
        if (appConfig.APP.ENV === 'development' && appConfig.AUTH.OTP_FIXED_CODE) {
            return appConfig.AUTH.OTP_FIXED_CODE;
        }
        return randomInt(0, 1_000_000).toString().padStart(6, '0');
    }

    private buildUserPayload(user: User, activeRoleId: number): UserPayload {
        return {
            id        : user.id,
            sex_id    : user.sex_id,
            avatar    : user.avatar_file
                ? { id: user.avatar_file.id, uri: user.avatar_file.uri ?? null, file_domain: user.avatar_file.file_domain ?? null }
                : { id: null, uri: user.avatar ?? null, file_domain: null },
            kh_name   : user.kh_name,
            en_name   : user.en_name,
            phone     : user.phone,
            email     : user.email ?? null,
            is_active : activeRoleId,
            roles     : user.roles.map(r => ({ id: r.id, name: r.name, slug: r.slug, color: r.color, icon: r.icon, is_default: r.id === activeRoleId })),
        };
    }

    private signAccessToken(payload: UserPayload): string {
        return jwt.sign({ user: payload }, jwtConstants.secret, { expiresIn: appConfig.AUTH.JWT_EXPIRES_IN });
    }

    private signRefreshToken(payload: UserPayload): string {
        return jwt.sign(
            { user: payload, type: 'refresh' },
            appConfig.AUTH.JWT_REFRESH_SECRET,
            { expiresIn: appConfig.AUTH.JWT_REFRESH_EXPIRES_IN },
        );
    }

    private buildTokenResponse(payload: UserPayload) {
        return {
            token: this.signAccessToken(payload),
            refresh_token: this.signRefreshToken(payload),
        };
    }

    private async getCurrentUser(id: number): Promise<User> {
        const user = await this.dataSourse.getRepository(User).findOne({
            where: { id },
            relations: ['roles', 'avatar_file'],
        });
        if (!user || user.deleted_at) throw new UnauthorizedException('User not found');
        return user;
    }

    private resolveClientInfo(req: any): ClientInfo {
        const userAgent = req.headers?.['user-agent'] || '';
        let browser = 'Unknown';
        if (userAgent.includes('Chrome')) browser = 'Chrome';
        else if (userAgent.includes('Firefox')) browser = 'Firefox';
        else if (userAgent.includes('Safari')) browser = 'Safari';
        else if (userAgent.includes('Edge')) browser = 'Edge';

        let platform = 'Unknown';
        if (userAgent.includes('Windows')) platform = 'Windows';
        else if (userAgent.includes('Mac')) platform = 'macOS';
        else if (userAgent.includes('Linux')) platform = 'Linux';
        else if (userAgent.includes('Android')) platform = 'Android';
        else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) platform = 'iOS';

        let os = 'Unknown';
        if (userAgent.includes('Windows NT 10')) os = 'Windows 10';
        else if (userAgent.includes('Windows NT 6.3')) os = 'Windows 8.1';
        else if (userAgent.includes('Windows NT 6.2')) os = 'Windows 8';
        else if (userAgent.includes('Mac OS X')) os = 'macOS';
        else if (userAgent.includes('Android')) os = 'Android';
        else if (userAgent.includes('iOS')) os = 'iOS';

        let device_type = 'desktop';
        if (userAgent.includes('Mobile') || userAgent.includes('Android')) device_type = 'mobile';
        else if (userAgent.includes('Tablet') || userAgent.includes('iPad')) device_type = 'tablet';

        const ip = req.headers?.['x-forwarded-for']?.split(',')[0]?.trim()
            || req.socket?.remoteAddress
            || null;

        return { ip, browser, platform, os, device_name: `${browser} on ${platform}`, device_type, user_agent: userAgent, location: undefined };
    }

    async login(loginDto: LoginRequestDto, req?: any) {
        try {
            const { username, password } = loginDto;
            const repo           = this.dataSourse.getRepository(User);
            const otprepo        = this.dataSourse.getRepository(UserOTP);
            const sessionRepo    = this.dataSourse.getRepository(UserSessions);
            const sessionLogRepo = this.dataSourse.getRepository(UserSessionLogs);

            // CHANGED: was findOne({ where: { phone: username } }) — phone only
            // NOW: createQueryBuilder supports phone OR email (case-insensitive)
            const user = await repo
                .createQueryBuilder('user')
                .leftJoinAndSelect('user.roles', 'roles')
                .where('user.phone = :username', { username })
                .orWhere('LOWER(user.email) = LOWER(:username)', { username })
                .getOne();

            if (!user) throw new BadRequestException('Invalid username or password');

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) throw new BadRequestException('Invalid username or password');

            const clientInfo = this.resolveClientInfo(req || {});
            const deviceId = req?.headers?.['x-device-id'] as string | undefined;

            const whereCondition: any = { user_id: user.id, browser: clientInfo.browser, platform: clientInfo.platform, is_active: true };
            if (deviceId) whereCondition.device_id = deviceId;

            let session = await sessionRepo.findOne({ where: whereCondition });

            if (session) {
                await sessionRepo.update(session.id, {
                    ip               : clientInfo.ip,
                    os               : clientInfo.os,
                    device_name      : clientInfo.device_name,
                    device_type      : clientInfo.device_type,
                    user_agent       : clientInfo.user_agent,
                    last_activity_at : new Date(),
                    logged_out_at    : null,
                    country_code     : clientInfo.location?.country_code,
                    region           : clientInfo.location?.region,
                    city             : clientInfo.location?.city,
                    latitude         : clientInfo.location?.latitude,
                    longitude        : clientInfo.location?.longitude,
                    timezone         : clientInfo.location?.timezone,
                });
            } else {
                session = await sessionRepo.save({
                    user_id          : user.id,
                    device_id        : deviceId ?? null,
                    device_name      : clientInfo.device_name,
                    platform         : clientInfo.platform,
                    os               : clientInfo.os,
                    browser          : clientInfo.browser,
                    device_type      : clientInfo.device_type,
                    user_agent       : clientInfo.user_agent,
                    ip               : clientInfo.ip,
                    country_code     : clientInfo.location?.country_code,
                    region           : clientInfo.location?.region,
                    city             : clientInfo.location?.city,
                    latitude         : clientInfo.location?.latitude,
                    longitude        : clientInfo.location?.longitude,
                    timezone         : clientInfo.location?.timezone,
                    login_method     : 1,
                    is_active        : true,
                    last_activity_at : new Date(),
                });
            }

            await sessionLogRepo.save({
                user_id     : user.id,
                device_id   : deviceId ?? null,
                device_name : clientInfo.device_name,
                platform    : clientInfo.platform,
                os          : clientInfo.os,
                browser     : clientInfo.browser,
                user_agent  : clientInfo.user_agent,
                device_type : clientInfo.device_type,
                ip          : clientInfo.ip ?? null,
            });

            const otp = this.generateOtp();
            await otprepo.delete({ user_id: user.id });
            await otprepo.save({ user_id: user.id, otp, expires_at: new Date(Date.now() + 2 * 60 * 1000) });

            return { status: 200, message: 'Success' };

        } catch (err: any) {
            console.log(err);
            throw new BadRequestException(err.message || 'Login failed');
        }
    }

    async verifyOtp(body: VerifyOtptDto) {
        try {
            const repo = this.dataSourse.getRepository(UserOTP);

            // CHANGED: was .where('user.phone = :phone', { phone: body.username })
            // NOW: supports phone OR email so OTP page works whether user logged in with phone or email
            const otpData = await repo
                .createQueryBuilder('otp')
                .leftJoinAndSelect('otp.user', 'user')
                .leftJoinAndSelect('user.roles', 'roles')
                .leftJoinAndSelect('user.avatar_file', 'avatar_file')
                .where('(user.phone = :username OR LOWER(user.email) = LOWER(:username))', { username: body.username })
                .andWhere('otp.otp = :otp', { otp: body.otp })
                .orderBy('otp.id', 'DESC')
                .getOne();

            if (!otpData) throw new BadRequestException('Invalid OTP');
            if (otpData.expires_at < new Date()) throw new BadRequestException('OTP expired');

            const user = otpData.user;
            const activeRoleId = user.roles[0]?.id;

            if (!activeRoleId) throw new BadRequestException('User does not have any valid roles');

            const payload = this.buildUserPayload(user, activeRoleId);
            const tokens  = this.buildTokenResponse(payload);

            await repo.delete({ id: otpData.id });

            return { status_code: 200, user: payload, ...tokens, message: 'Success' };

        } catch (err: any) {
            throw new BadRequestException(err.message);
        }
    }

    // CHANGED: parameter renamed from 'phone' to 'username', lookup now supports phone OR email
    async resendOtp(username: string) {
        try {
            const userRepo = this.dataSourse.getRepository(User);
            const otpRepo  = this.dataSourse.getRepository(UserOTP);

            const user = await userRepo
                .createQueryBuilder('user')
                .where('user.phone = :username', { username })
                .orWhere('LOWER(user.email) = LOWER(:username)', { username })
                .getOne();
            if (!user) throw new BadRequestException('User not found');

            const otp = this.generateOtp();
            await otpRepo.delete({ user_id: user.id });
            await otpRepo.save({ user_id: user.id, otp, expires_at: new Date(Date.now() + 5 * 60 * 1000) });

            return { status_code: 200, message: 'OTP resent successfully' };

        } catch (err: any) {
            throw new BadRequestException(err.message);
        }
    }

    async refreshToken(refreshToken: string) {
        try {
            const decoded = jwt.verify(refreshToken, appConfig.AUTH.JWT_REFRESH_SECRET) as RefreshPayload;

            if (decoded.type !== 'refresh' || !decoded.user?.id) {
                throw new UnauthorizedException('Invalid refresh token');
            }

            const user = await this.getCurrentUser(decoded.user.id);
            const requestedRoleId = decoded.user.is_active;
            const activeRoleId = user.roles.some((role) => role.id === requestedRoleId)
                ? requestedRoleId
                : user.roles[0]?.id;

            if (!activeRoleId) throw new UnauthorizedException('User does not have any valid roles');

            const payload = this.buildUserPayload(user, activeRoleId);
            const tokens  = this.buildTokenResponse(payload);

            return { status_code: 200, user: payload, ...tokens, message: 'Token refreshed successfully' };
        } catch (err) {
            if (err instanceof UnauthorizedException) throw err;
            throw new UnauthorizedException('Invalid or expired refresh token');
        }
    }
}
```

---

### FILE 3 — `web/src/app/core/auth/auth.service.ts`

**What changed:**
- `sendOtp()` — URL was `/account/auth/send-otp` (does not exist), changed to `/auth/resend-otp`
- Added `forgetPassword()` — calls `POST /auth/forget-password`
- Added `resetPasswordWithOtp()` — calls `POST /auth/reset-password`

Only the 3 changed/added methods are shown below. The rest of the file is unchanged.

```ts
// CHANGED: URL was /account/auth/send-otp (endpoint does not exist)
// NOW: correct endpoint /auth/resend-otp
sendOtp(credentials: { username: string }): Observable<{ status_code: number; message: string }> {
    return this._httpClient
        .post<{ status_code: number; message: string }>(
            `${env.API_BASE_URL}/auth/resend-otp`,
            credentials
        )
        .pipe(switchMap((response) => of(response)));
}

// ADDED: calls POST /auth/forget-password to generate and store OTP in DB
forgetPassword(username: string): Observable<{ status_code: number; go_to_reset_password: boolean; contact: string; message: string }> {
    return this._httpClient.post<any>(`${env.API_BASE_URL}/auth/forget-password`, { username });
}

// ADDED: calls POST /auth/reset-password to verify OTP and update the password
resetPasswordWithOtp(body: { username: string; otp: string; new_password: string; confirm_password: string }): Observable<{ status_code: number; message: string }> {
    return this._httpClient.post<any>(`${env.API_BASE_URL}/auth/reset-password`, body);
}
```

---

### FILE 4 — `web/src/app/resources/r1-account/auth/reset-password/reset-password.component.ts`

**What changed:**
- `showOtp()` — was opening OTP dialog directly with no API call. Now calls `forgetPassword()` API first, then opens dialog. Also passes `otp` from dialog result into the password dialog data.
- `validateInput()` — was testing raw input against phone regex, so `087 600 063` (with spaces) failed. Now strips non-digits first.

```ts
// ...existing imports...
import { CommonModule }                                     from '@angular/common';
import { Component, OnInit }                                from '@angular/core';
import { ReactiveFormsModule, FormsModule }                 from '@angular/forms';
import { UntypedFormBuilder, UntypedFormGroup, Validators } from '@angular/forms';
import { Router, RouterLink }                               from '@angular/router';
import { MatDialog, MatDialogModule }                       from '@angular/material/dialog';
import { MatButtonModule }                                  from '@angular/material/button';
import { MatFormFieldModule }                               from '@angular/material/form-field';
import { MatInputModule }                                   from '@angular/material/input';
import { MatIconModule }                                    from '@angular/material/icon';
import { MatProgressSpinnerModule }                         from '@angular/material/progress-spinner';
import { TranslocoModule }                                  from '@ngneat/transloco';
import { env }                                              from 'envs/env';
import { SnackbarService }                                  from 'helper/services/snack-bar/snack-bar.service';
import { ErrorHandleService }                               from 'app/shared/error-handle.service';
import { AuthService }                                      from 'app/core/auth/auth.service';
import { LanguagesComponent }                               from 'app/layout/common/languages/languages.component';

@Component({
    selector    : 'app-reset-password',
    templateUrl : './reset-password.component.html',
    styleUrls   : ['./reset-password.component.scss'],
    standalone  : true,
    imports     : [
        CommonModule, MatButtonModule, MatFormFieldModule, MatInputModule,
        MatIconModule, MatProgressSpinnerModule, TranslocoModule,
        ReactiveFormsModule, FormsModule, RouterLink, MatDialogModule, LanguagesComponent
    ]
})
export class ResetPasswordComponent implements OnInit {
    public phoneOrEmail : string = '';
    public resetPasswordForm!: UntypedFormGroup;
    public isLoading    = false;
    public appVersion   : string = env.APP_VERSION;
    public isInputValid : boolean = false;

    constructor(
        private _formBuilder        : UntypedFormBuilder,
        private _authService        : AuthService,
        private _router             : Router,
        private _snackbarService    : SnackbarService,
        private _errorHandleService : ErrorHandleService,
        private _matDialog          : MatDialog
    ) {}

    ngOnInit(): void {
        this.resetPasswordForm = this._formBuilder.group({
            newPassword     : ['', [Validators.required, Validators.minLength(6)]],
            confirmPassword : ['', [Validators.required, Validators.minLength(6)]]
        }, {
            validators: this.passwordMatchValidator
        });
    }

    passwordMatchValidator(group: UntypedFormGroup): { [key: string]: boolean } | null {
        const password        = group.get('newPassword')?.value;
        const confirmPassword = group.get('confirmPassword')?.value;
        return password === confirmPassword ? null : { mismatch: true };
    }

    showOtp(event?: Event): void {
        event?.preventDefault();
        this.validateInput();
        if (!this.isInputValid) {
            this._snackbarService.openSnackBar('សូមបញ្ចូលអ៊ីមែលត្រឹមត្រូវ ឬ លេខទូរស័ព្ទយ៉ាងតិច 9 ខ្ទង់', 'error');
            return;
        }

        const digitsOnly  = (this.phoneOrEmail || '').replace(/\D/g, '');
        const emailRegex  = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        const payloadValue = emailRegex.test(this.phoneOrEmail) ? this.phoneOrEmail : digitsOnly;

        this.isLoading = true;

        // CHANGED: was just opening OTP dialog directly — no API call, no OTP in DB
        // NOW: calls forgetPassword() first so OTP is generated and saved in DB
        this._authService.forgetPassword(payloadValue).subscribe({
            next: () => {
                this.isLoading = false;
                localStorage.setItem('email', payloadValue);

                import('../rest-password-otp/index').then(m => {
                    const dialogRef = this._matDialog.open(m.AuthOTPForResetPasswordComponent, {
                        width        : '26rem',
                        panelClass   : 'custom-otp-dialog',
                        data         : { email: payloadValue },
                        disableClose : true,
                        backdropClass: 'otp-backdrop'
                    });

                    dialogRef.afterClosed().subscribe(result => {
                        if (result?.verified) {
                            import('../../login-code/create-password').then(m => {
                                this._matDialog.open(m.PasswordComponent, {
                                    width        : '24rem',
                                    maxHeight    : 'none',
                                    panelClass   : 'custom-password-dialog',
                                    data         : {
                                        email   : payloadValue,
                                        username: payloadValue,
                                        otp     : result.otp,  // CHANGED: was missing — otp never passed to password dialog
                                        type    : 'resetPassword'
                                    },
                                    disableClose : true,
                                    backdropClass: 'password-backdrop'
                                });
                            });
                        }
                    });
                });
            },
            error: err => {
                this.isLoading = false;
                this._errorHandleService.handleHttpError(err);
            }
        });
    }

    // CHANGED: was phoneRegex.test(this.phoneOrEmail) — failed if user typed spaces e.g. "087 600 063"
    // NOW: strips non-digits first, then tests, so spaces/dashes are ignored
    validateInput(): void {
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        const phoneRegex = /^\d{9,}$/;
        const digitsOnly = (this.phoneOrEmail || '').replace(/\D/g, '');
        this.isInputValid = emailRegex.test(this.phoneOrEmail) || phoneRegex.test(digitsOnly);
    }
}
```

---

### FILE 5 — `web/src/app/resources/r1-account/auth/rest-password-otp/index.ts`

**What changed:**
- `resendOtp()` — was resetting only local state with no API call. Now calls `forgetPassword()` so a real new OTP is saved in DB.
- `verify()` — was hardcoded `if (this.otpCode === '123456')`, any other real OTP always failed. Now just closes dialog and passes OTP to caller. Real verification happens at the reset-password API step.

Only the two changed methods are shown. The rest of the file (inputs, countdown, paste, keydown handlers) is unchanged.

```ts
// CHANGED: was only resetting local UI state, no API call
// NOW: calls forgetPassword() so a fresh OTP is generated and saved in DB
resendOtp(): void {
    this.isLoading = true;
    this.otpFailed = false;

    this._authService.forgetPassword(this.email).subscribe({
        next: () => {
            this.isLoading = false;
            this.reSendOtp = false;
            this.remainingTime = 60;
            this.clearAllInput();
            this.checkValid();
            this.startCountdown();
            this._snackbarService.openSnackBar('OTP បានផ្ញើជាថ្មីដោយជោគជ័យ', 'success');
        },
        error: err => {
            this.isLoading = false;
            this._errorHandleService.handleHttpError(err);
        }
    });
}

// CHANGED: was hardcoded — only accepted "123456", set otpFailed=true for anything else
// NOW: closes dialog with the actual typed OTP code — API verifies it at reset-password step
verify(): void {
    if (!this.canSubmit || this.isLoading) return;
    this.otpFailed = false;
    this.dialogRef.close({ verified: true, otp: this.otpCode });
}
```

---

### FILE 6 — `web/src/app/resources/r1-account/login-code/create-password/password.component.ts`

**What changed:**
- Added `otp` property — reads from dialog data, was never received before
- `signIn()` resetPassword branch — was calling `updatePassword()` → wrong endpoint `/account/auth/reset-to-new-password`. Now calls `resetPasswordWithOtp()` → correct endpoint `/auth/reset-password` with all required fields

Only the changed parts are shown. Imports, template, and signUp branch are unchanged.

```ts
export class PasswordComponent implements OnInit {

    public form     : UntypedFormGroup;
    public isSaving : boolean = false;
    @ViewChild('signInNgForm') signInNgForm: NgForm;
    public username : string;
    public otp      : string;   // ADDED: stores OTP passed from OTP dialog
    public type     : string;
    isLoading       : boolean = false;
    data            : any;
    route_link      : string;
    accessToken     : string;

    constructor(
        private _authService        : AuthService,
        private _formBuilder        : UntypedFormBuilder,
        private _router             : Router,
        private _snackbarService    : SnackbarService,
        private _errorHandleService : ErrorHandleService,
        private route               : ActivatedRoute,
        public dialogRef            : MatDialogRef<PasswordComponent>,
        @Inject(MAT_DIALOG_DATA) public dialogData: any = {}
    ) {
        if (this.dialogData?.username || this.dialogData?.email) {
            this.username = this.dialogData.username || this.dialogData.email;
            this.otp      = this.dialogData.otp || '';   // ADDED: read otp from dialog data
            this.type     = this.dialogData.type || 'resetPassword';
            this.data     = this.dialogData.data || {};
        } else {
            const navigation = this._router.getCurrentNavigation();
            if (navigation?.extras.state) {
                this.username = navigation.extras.state['username'];
                this.otp      = navigation.extras.state['otp'] || '';  // ADDED
                this.type     = navigation.extras.state['type'];
                this.data     = navigation.extras.state['data'];
            } else {
                this.username = history.state.username;
                this.otp      = history.state.otp || '';  // ADDED
                this.type     = history.state.type;
                this.data     = history.state.data;
            }
        }

        if (this.type === 'signUp') {
            this.route_link = '/auth/sign-up';
        } else {
            this.route_link = '/auth';
        }
    }

    ngOnInit(): void {
        this.form = this._formBuilder.group({
            password: ['', [Validators.required]]
        });
    }

    signIn(): void {
        if (!this.form) return;
        this.isLoading = true;

        if (this.type === 'signUp') {
            // signUp branch unchanged
            const credentials = {
                finalToken: this.data.finalToken,
                group_id  : this.data.data.group_id,
                name      : this.data.data.name,
                password  : this.form.value.password,
                phone     : this.data.data.phone,
                school_id : this.data.data.school_id,
            };
            this._authService.signUpFinal(credentials).subscribe({
                next: (res: any) => {
                    this._authService.accessToken = res?.access_token;
                    this._authService.verified(res?.access_token);
                    localStorage.setItem('refreshToken', res?.refresh_token);
                    this._router.navigateByUrl('');
                    this.isLoading = false;
                    this._snackbarService.openSnackBar('ចូលប្រព័ន្ធបានដោយជោគជ័យ', GlobalConstants.success);
                },
                error: err => {
                    this.form.enable();
                    this.signInNgForm.resetForm();
                    this._errorHandleService.handleHttpError(err);
                }
            });
        } else {
            // CHANGED: was updatePassword() → POST /account/auth/reset-to-new-password (wrong endpoint, missing otp)
            // NOW: resetPasswordWithOtp() → POST /auth/reset-password with all required fields
            const credentials = {
                username        : this.username,
                otp             : this.otp,
                new_password    : this.form.value.password,
                confirm_password: this.form.value.password,  // same value — API just checks they match
            };
            this._authService.resetPasswordWithOtp(credentials).subscribe({
                next: () => {
                    this.isLoading = false;
                    this.dialogRef.close();
                    localStorage.removeItem('email');
                    this._router.navigateByUrl('/auth');
                    this._snackbarService.openSnackBar('កំណត់ពាក្យសម្ងាត់ថ្មីបានដោយជោគជ័យ', GlobalConstants.success);
                },
                error: err => {
                    this.isLoading = false;
                    this.form.enable();
                    this._errorHandleService.handleHttpError(err);
                }
            });
        }
    }

    // password strength getters — unchanged
    get password()       { return this.form.get('password')?.value || ''; }
    get hasMinLength()   { return this.password.length >= 6; }
    get hasLowerCase()   { return /[a-z]/.test(this.password); }
    get hasUpperCase()   { return /[A-Z]/.test(this.password); }
    get hasSpecialChars(){ const m = this.password.match(/[#@!$*]/g); return m !== null && m.length >= 2; }
    get matchedCount()   {
        let c = 0;
        if (this.hasMinLength)   c++;
        if (this.hasLowerCase)   c++;
        if (this.hasUpperCase)   c++;
        if (this.hasSpecialChars) c++;
        return c;
    }

    navigateBack(): void { this._router.navigateByUrl(this.route_link); }
}
```

---

### FILE 7 — `web/src/helper/enums/role.enum.ts`

**What changed:** `USER` value was `'អ្នកប្រើប្រាស់'` (Khmer) but the DB role name is `'User'` (English) — they never matched so regular users could never be identified after login.

```ts
export enum RoleEnum {
    ADMIN      = 'Administrator',
    ORG_ADMIN  = 'Organization Admin',
    BANK_ADMIN = 'Bank Admin',
    VOLUNTEER  = 'អ្នកស្ម័គ្រចិត្ត',
    USER       = 'User',   // CHANGED: was 'អ្នកប្រើប្រាស់' — did not match DB role name
}
```

---

### FILE 8 — `web/src/app/core/auth/resolvers/role.resolver.ts`

**What changed:** Added `case RoleEnum.USER` — was missing so User role fell to `default: return '/auth'` which sent them back to login in an infinite loop.

```ts
import { inject }      from "@angular/core";
import { Router }      from "@angular/router";
import { RoleEnum }    from "helper/enums/role.enum";
import { UserPayload } from 'helper/interfaces/payload.interface';
import jwt_decode      from 'jwt-decode';
import { of }          from "rxjs";
import { AuthService } from "../auth.service";

export const getRoleDefaultUrl = (roleName?: string): string => {
    switch (roleName) {
        case RoleEnum.ADMIN:
            return '/admin/home';
        case RoleEnum.USER:        // ADDED: was missing — User role hit default and went back to /auth (loop)
            return '/admin/home';
        case RoleEnum.ORG_ADMIN:
            return '/org/invoice';
        case RoleEnum.BANK_ADMIN:
            return '/bank/invoice';
        default:
            return '/auth';
    }
};

export const roleResolver = (allowedRoles: string[]) => {
    return () => {
        const router       = inject(Router);
        const token        = inject(AuthService).accessToken;
        const tokenPayload : UserPayload = jwt_decode(token);

        const is_active = tokenPayload.user.is_active;
        const role      = tokenPayload.user.roles.find(role => role.id === is_active) ?? tokenPayload.user.roles[0];

        if (!role) {
            router.navigateByUrl('/auth');
            return of(false);
        }

        const isValidRole = allowedRoles.includes(role.name);

        if (!isValidRole) {
            router.navigateByUrl(getRoleDefaultUrl(role.name));
            return of(false);
        }

        return of(allowedRoles);
    };
};
```

---

### FILE 9 — `web/src/app/app.routes.ts`

**What changed:** Admin route `roleResolver` — was `[RoleEnum.ADMIN]` only. User role was blocked and caused an infinite redirect loop (`/admin/home` → blocked → `/admin/home` → blocked…).

Only the changed line is shown:

```ts
// CHANGED: was roleResolver([RoleEnum.ADMIN]) — blocked User role, caused infinite redirect
// NOW: allows both Admin and User to access /admin routes
{
    path: 'admin',
    resolve: {
        role: roleResolver([RoleEnum.ADMIN, RoleEnum.USER])
    },
    loadChildren: () => import('app/resources/r2-admin/route')
},
```
