import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import {Router} from '@angular/router';
import {Message, MessageService} from 'primeng/api';
import {AuthService} from 'src/app/zynerator/security/shared/service/Auth.service';
import {LayoutService} from 'src/app/layout/service/app.layout.service';
import {UserDto} from "src/app/zynerator/security/shared/model/User.model";
import {environment} from "src/environments/environment";

@Component({
  selector: 'app-login-admin',
  templateUrl: './login-admin.component.html',
  styleUrls: ['./login-admin.component.css']
})
export class LoginAdminComponent implements OnInit {
  public error: string = null;
  readonly API = environment.loginUrl;
   googleLoginOptions = {
    scope: 'profile email',
    plugin_name:'sample_login'
  };

  private _authenticatedUser = new UserDto();
    loginForm = new FormGroup({
        username: new FormControl('',Validators.required),
        password: new FormControl('',Validators.required)
    });

    clicked = false;
    messages: Message[] = [];

    constructor(private authService: AuthService,public layoutService: LayoutService, private router: Router, private messageService: MessageService) { }

    ngOnInit(): void {
        this.messages = [];
    }

    submit(){
        this.clicked = true;
        if (this.loginForm.valid) {
            const formValues = this.loginForm.value;
            const username = formValues.username;
            const passowrd = formValues.password;
            this.authService.login(username, passowrd);
        }else{
            this.messageService.add({
                severity: 'error',
                summary: 'Error',
                detail:  'fill in all fields'
            });
        }
    }

    public signInWithGoogle(): void {
    /*
     this.oauthService.signIn(GoogleLoginProvider.PROVIDER_ID,this.googleLoginOptions).then(
        data => {
          this.socialUser = data;
        const role = new RoleDto();
        role.authority = 'ROLE_ADMIN' ;
        const roleUser = new RoleUserDto();
        roleUser.role = role;
        this.user.accountNonExpired=true;
        this.user.accountNonLocked=true;
        this.user.credentialsNonExpired=true;
        this.user.enabled=false;
        this.user.passwordChanged=false;
        this.user.firstName = data.firstName;
        this.user.lastName = data.lastName;
        this.user.phone = null;
        this.user.username = data.email;
        this.user.password = Date.now()+"-"+data.email;
        this.user.email = data.email;
        this.user.roleUsers = new Array<RoleUserDto>();
        this.user.roleUsers.push(roleUser);
          this.authService.loginUsingGoogle();
        }
      ).catch(
        err => {
          console.log(err);
        }
      );
  */
  }

    register(){
        this.router.navigate(['/admin/register']);
    }
    forget(){
        this.router.navigate(['/admin/changePassword']);
    }
    get user(): UserDto {
      return this.authService.user;
  }

  set user(value: UserDto) {
      this.authService.user = value;
  }


/////////////////////////// GitHub///////////////////////////////


  // signInWithGitHub() {
  //   const clientId = 'Ov23li2SwsDQHwOEAFum';
  //   const redirectUri = 'http://localhost:4200/callback';

  //   window.location.href = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&prompt=login`;
  // }






}
