package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/urfave/cli/v2"
)

const name = "nostr-mute"

const version = "0.0.2"

var revision = "HEAD"

func pksk(nsec string) (string, string, error) {
	if nsec == "" {
		return "", "", errors.New("NOSTR_MUTE_NSEC is not set")
	}

	var sk string
	if _, s, err := nip19.Decode(nsec); err == nil {
		sk = s.(string)
	} else {
		return "", "", err
	}
	var pk string
	if pub, err := nostr.GetPublicKey(sk); err == nil {
		if _, err := nip19.EncodePublicKey(pub); err != nil {
			return "", "", err
		}
		pk = pub
	} else {
		return "", "", err
	}
	return pk, sk, nil
}

func doList(cCtx *cli.Context) error {
	relays := cCtx.StringSlice("relays")
	encrypt := cCtx.Bool("encrypt")

	pk, sk, err := pksk(os.Getenv("NOSTR_MUTE_NSEC"))
	if err != nil {
		return err
	}

	ctx := context.Background()
	ms := nostr.MultiStore{}
	for _, r := range relays {
		rr, err := nostr.RelayConnect(ctx, r)
		if err == nil {
			ms = append(ms, rr)
		}
	}

	filter := nostr.Filter{
		Kinds:   []int{nostr.KindMuteList},
		Authors: []string{pk},
	}
	evs, err := ms.QuerySync(ctx, filter)
	if err != nil {
		return err
	}

	if len(evs) != 1 {
		return errors.New("mute list not found")
	}

	var pp [][]string
	if encrypt {
		var content string
		if strings.Contains(evs[0].Content, "=?iv=") {
			ss, err := nip04.ComputeSharedSecret(pk, sk)
			if err != nil {
				return err
			}

			content, err = nip04.Decrypt(evs[0].Content, ss)
			if err != nil {
				return err
			}
		} else {
			content = evs[0].Content
		}
		err = json.Unmarshal([]byte(content), &pp)
		if err != nil {
			return err
		}
	} else {
		for _, tag := range evs[0].Tags {
			pp = append(pp, tag)
		}
	}
	for _, p := range pp {
		if len(p) != 2 {
			continue
		}
		fmt.Println(p[0], p[1])
	}

	return nil
}

func doExport(cCtx *cli.Context) error {
	relays := cCtx.StringSlice("relays")
	encrypt := cCtx.Bool("encrypt")

	pk, sk, err := pksk(os.Getenv("NOSTR_MUTE_NSEC"))
	if err != nil {
		return err
	}

	ctx := context.Background()
	ms := nostr.MultiStore{}
	for _, r := range relays {
		rr, err := nostr.RelayConnect(ctx, r)
		if err == nil {
			ms = append(ms, rr)
		}
	}

	filter := nostr.Filter{
		Kinds:   []int{nostr.KindMuteList},
		Authors: []string{pk},
	}
	evs, err := ms.QuerySync(ctx, filter)
	if err != nil {
		return err
	}

	if len(evs) != 1 {
		return errors.New("mute list not found")
	}

	var content string
	if encrypt {
		if strings.Contains(evs[0].Content, "=?iv=") {
			ss, err := nip04.ComputeSharedSecret(pk, sk)
			if err != nil {
				return err
			}

			content, err = nip04.Decrypt(evs[0].Content, ss)
			if err != nil {
				return err
			}
		} else {
			content = evs[0].Content
		}
	} else {
		b, err := json.Marshal(evs[0].Tags)
		if err != nil {
			return err
		}
		content = string(b)
	}
	fmt.Println(content)

	return nil
}

func doImport(cCtx *cli.Context) error {
	relays := cCtx.StringSlice("relays")
	encrypt := cCtx.Bool("encrypt")
	replace := cCtx.Bool("replace")

	pk, sk, err := pksk(os.Getenv("NOSTR_MUTE_NSEC"))
	if err != nil {
		return err
	}

	ctx := context.Background()
	ms := nostr.MultiStore{}
	for _, r := range relays {
		rr, err := nostr.RelayConnect(ctx, r)
		if err == nil {
			ms = append(ms, rr)
		}
	}

	filter := nostr.Filter{
		Kinds:   []int{nostr.KindMuteList},
		Authors: []string{pk},
	}
	evs, err := ms.QuerySync(ctx, filter)
	if err != nil {
		return err
	}

	ev := nostr.Event{}
	if len(evs) == 1 {
		ev = *evs[0]
	} else {
		ev.PubKey = pk
		ev.Kind = nostr.KindMuteList
	}

	var ppa [][]string
	if cCtx.Args().Present() {
		f, err := os.Open(cCtx.Args().First())
		if err != nil {
			return err
		}
		defer f.Close()
		err = json.NewDecoder(f).Decode(&ppa)
		if err != nil {
			return err
		}
	} else {
		err := json.NewDecoder(os.Stdin).Decode(&ppa)
		if err != nil {
			return err
		}
	}

	if encrypt {
		var pp [][]string
		if !replace {
			var content string
			if strings.Contains(evs[0].Content, "=?iv=") {
				ss, err := nip04.ComputeSharedSecret(pk, sk)
				if err != nil {
					return err
				}

				content, err = nip04.Encrypt(string(evs[0].Content), ss)
				if err != nil {
					return err
				}
			} else {
				content = evs[0].Content
			}
			err = json.Unmarshal([]byte(content), &pp)
			if err != nil {
				return err
			}
		}
		for _, p := range ppa {
			if !exists(pp, p) {
				pp = append(pp, p)
			}
		}

		b, err := json.Marshal(pp)
		if err != nil {
			return err
		}
		ev.Content = string(b)
	} else {
		tags := [][]string{}
		if !replace {
			for _, t := range ev.Tags {
				tags = append(tags, []string(t))
			}
		}
		for _, p := range ppa {
			if !exists(tags, p) {
				ev.Tags = ev.Tags.AppendUnique(nostr.Tag(p))
			}
		}
	}

	ev.CreatedAt = nostr.Now()

	if err := ev.Sign(sk); err != nil {
		return err
	}

	if cCtx.Bool("dryrun") {
		fmt.Println(ev.String())
		return nil
	}
	return ms.Publish(ctx, ev)
}

func exists(pp [][]string, p []string) bool {
	if len(p) != 2 {
		return false
	}
	for _, t := range pp {
		if !slices.Equal(p, t) {
			continue
		}
		return true
	}
	return false
}

func doAdd(cCtx *cli.Context) error {
	relays := cCtx.StringSlice("relays")
	encrypt := cCtx.Bool("encrypt")

	pk, sk, err := pksk(os.Getenv("NOSTR_MUTE_NSEC"))
	if err != nil {
		return err
	}

	ctx := context.Background()
	ms := nostr.MultiStore{}
	for _, r := range relays {
		rr, err := nostr.RelayConnect(ctx, r)
		if err == nil {
			ms = append(ms, rr)
		}
	}

	filter := nostr.Filter{
		Kinds:   []int{nostr.KindMuteList},
		Authors: []string{pk},
	}
	evs, err := ms.QuerySync(ctx, filter)
	if err != nil {
		return err
	}

	ev := nostr.Event{}
	if len(evs) == 1 {
		ev = *evs[0]
	} else {
		ev.PubKey = pk
		ev.Kind = nostr.KindMuteList
	}

	var ppa [][]string

	for _, p := range cCtx.StringSlice("p") {
		if _, pub, err := nip19.Decode(p); err == nil {
			ppa = append(ppa, []string{"p", pub.(string)})
		} else {
			ppa = append(ppa, []string{"p", p})
		}
	}

	for _, e := range cCtx.StringSlice("e") {
		if _, pub, err := nip19.Decode(e); err == nil {
			ppa = append(ppa, []string{"e", pub.(string)})
		} else {
			ppa = append(ppa, []string{"e", e})
		}
	}

	if encrypt {
		var content string
		if strings.Contains(evs[0].Content, "=?iv=") {
			ss, err := nip04.ComputeSharedSecret(pk, sk)
			if err != nil {
				return err
			}

			content, err = nip04.Encrypt(string(evs[0].Content), ss)
			if err != nil {
				return err
			}
		} else {
			content = evs[0].Content
		}
		var pp [][]string
		err = json.Unmarshal([]byte(content), &pp)
		if err != nil {
			return err
		}
		for _, p := range ppa {
			if !exists(pp, p) {
				pp = append(pp, p)
			}
		}

		b, err := json.Marshal(pp)
		if err != nil {
			return err
		}
		ev.Content = string(b)
	} else {
		tags := [][]string{}
		for _, t := range ev.Tags {
			tags = append(tags, []string(t))
		}
		for _, p := range ppa {
			if !exists(tags, p) {
				ev.Tags = ev.Tags.AppendUnique(nostr.Tag(p))
			}
		}
	}

	ev.CreatedAt = nostr.Now()

	if err := ev.Sign(sk); err != nil {
		return err
	}

	if cCtx.Bool("dryrun") {
		fmt.Println(ev.String())
		return nil
	}
	return ms.Publish(ctx, ev)
}

func doImportP(cCtx *cli.Context) error {
	relays := cCtx.StringSlice("relays")
	encrypt := cCtx.Bool("encrypt")

	pk, sk, err := pksk(os.Getenv("NOSTR_MUTE_NSEC"))
	if err != nil {
		return err
	}

	ctx := context.Background()
	ms := nostr.MultiStore{}
	for _, r := range relays {
		rr, err := nostr.RelayConnect(ctx, r)
		if err == nil {
			ms = append(ms, rr)
		}
	}

	filter := nostr.Filter{
		Kinds:   []int{nostr.KindMuteList},
		Authors: []string{pk},
	}
	evs, err := ms.QuerySync(ctx, filter)
	if err != nil {
		return err
	}

	ev := nostr.Event{}
	if len(evs) == 1 {
		ev = *evs[0]
	} else {
		ev.PubKey = pk
		ev.Kind = nostr.KindMuteList
	}

	var ppa [][]string
	if cCtx.Args().Present() {
		f, err := os.Open(cCtx.Args().First())
		if err != nil {
			return err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			p := scanner.Text()
			if _, pub, err := nip19.Decode(p); err == nil {
				ppa = append(ppa, []string{"p", pub.(string)})
			} else {
				ppa = append(ppa, []string{"p", p})
			}
		}
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			p := scanner.Text()
			if _, pub, err := nip19.Decode(p); err == nil {
				ppa = append(ppa, []string{"p", pub.(string)})
			} else {
				ppa = append(ppa, []string{"p", p})
			}
		}
	}

	if encrypt {
		var content string
		if strings.Contains(evs[0].Content, "=?iv=") {
			ss, err := nip04.ComputeSharedSecret(pk, sk)
			if err != nil {
				return err
			}

			content, err = nip04.Encrypt(string(evs[0].Content), ss)
			if err != nil {
				return err
			}
		} else {
			content = evs[0].Content
		}
		var pp [][]string
		err = json.Unmarshal([]byte(content), &pp)
		if err != nil {
			return err
		}
		for _, p := range ppa {
			if !exists(pp, p) {
				pp = append(pp, p)
			}
		}

		b, err := json.Marshal(pp)
		if err != nil {
			return err
		}
		ev.Content = string(b)
	} else {
		tags := [][]string{}
		for _, t := range ev.Tags {
			tags = append(tags, []string(t))
		}
		for _, p := range ppa {
			if !exists(tags, p) {
				ev.Tags = ev.Tags.AppendUnique(nostr.Tag(p))
			}
		}
	}

	ev.CreatedAt = nostr.Now()

	if err := ev.Sign(sk); err != nil {
		return err
	}

	if cCtx.Bool("dryrun") {
		fmt.Println(ev.String())
		return nil
	}
	return ms.Publish(ctx, ev)
}

func doRemove(cCtx *cli.Context) error {
	relays := cCtx.StringSlice("relays")
	encrypt := cCtx.Bool("encrypt")

	pk, sk, err := pksk(os.Getenv("NOSTR_MUTE_NSEC"))
	if err != nil {
		return err
	}

	ctx := context.Background()
	ms := nostr.MultiStore{}
	for _, r := range relays {
		rr, err := nostr.RelayConnect(ctx, r)
		if err == nil {
			ms = append(ms, rr)
		}
	}

	filter := nostr.Filter{
		Kinds:   []int{nostr.KindMuteList},
		Authors: []string{pk},
	}
	evs, err := ms.QuerySync(ctx, filter)
	if err != nil {
		return err
	}

	ev := nostr.Event{}
	if len(evs) == 1 {
		ev = *evs[0]
	} else {
		ev.PubKey = pk
		ev.Kind = nostr.KindMuteList
	}

	var ppa [][]string

	for _, p := range cCtx.StringSlice("p") {
		if _, pub, err := nip19.Decode(p); err == nil {
			ppa = append(ppa, []string{"p", pub.(string)})
		} else {
			ppa = append(ppa, []string{"p", p})
		}
	}

	for _, e := range cCtx.StringSlice("e") {
		if _, pub, err := nip19.Decode(e); err == nil {
			ppa = append(ppa, []string{"e", pub.(string)})
		} else {
			ppa = append(ppa, []string{"e", e})
		}
	}

	if encrypt {
		var content string
		if strings.Contains(evs[0].Content, "=?iv=") {
			ss, err := nip04.ComputeSharedSecret(pk, sk)
			if err != nil {
				return err
			}

			content, err = nip04.Encrypt(string(evs[0].Content), ss)
			if err != nil {
				return err
			}
		} else {
			content = evs[0].Content
		}
		var pp [][]string
		err = json.Unmarshal([]byte(content), &pp)
		if err != nil {
			return err
		}
		pp = slices.DeleteFunc(pp, func(p []string) bool {
			return exists(pp, p)
		})

		b, err := json.Marshal(pp)
		if err != nil {
			return err
		}
		ev.Content = string(b)
	} else {
		tags := [][]string{}
		for _, t := range ev.Tags {
			tags = append(tags, []string(t))
		}
		ev.Tags = slices.DeleteFunc(ev.Tags, func(p nostr.Tag) bool {
			return exists(tags, []string(p))
		})
	}

	ev.CreatedAt = nostr.Now()

	if err := ev.Sign(sk); err != nil {
		return err
	}

	if cCtx.Bool("dryrun") {
		fmt.Println(ev.String())
		return nil
	}
	return ms.Publish(ctx, ev)
}

func doVersion(cCtx *cli.Context) error {
	fmt.Println(version)
	return nil
}

func main() {
	relays := strings.Split(os.Getenv("NOSTR_MUTE_RELAYS"), ",")
	if len(relays) == 0 || relays[0] == "" {
		relays = []string{"wss://relay.nostr.band"}
	}

	app := &cli.App{
		Usage:       "A cli application for nostr mute list",
		Description: "A cli application for nostr mute list",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "relays", Usage: "relays", Value: cli.NewStringSlice(relays...)},
			&cli.BoolFlag{Name: "encrypt", Usage: "encrypt", Value: true},
			&cli.BoolFlag{Name: "dryrun", Usage: "dryrun", Value: false},
		},
		Commands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "show mute list",
				UsageText: "nostr-mute list",
				Action:    doList,
			},
			{
				Name:      "export",
				Usage:     "export mute list",
				UsageText: "nostr-mute export > mute.json",
				Action:    doExport,
			},
			{
				Name:      "add",
				Usage:     "add to mute list",
				UsageText: "nostr-mute add -p npub1xxx -e note1xxx",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{Name: "p", Usage: "p"},
					&cli.StringSliceFlag{Name: "e", Usage: "e"},
				},
				Action: doAdd,
			},
			{
				Name:      "import",
				Usage:     "import mute import",
				UsageText: "nostr-mute import < mute.json",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "replace", Usage: "replace"},
				},
				Action: doImport,
			},
			{
				Name:      "import-p",
				Usage:     "import p to mute list",
				UsageText: "nostr-mute import-p < mute.txt",
				Action:    doImportP,
			},
			{
				Name:  "remove",
				Usage: "remove from mute list",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{Name: "p", Usage: "p"},
					&cli.StringSliceFlag{Name: "e", Usage: "e"},
				},
				Action: doRemove,
			},
			{
				Name:      "version",
				Usage:     "show version",
				UsageText: "nostr-mute version",
				HelpName:  "version",
				Action:    doVersion,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
